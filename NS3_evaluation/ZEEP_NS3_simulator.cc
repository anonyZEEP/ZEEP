#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/propagation-module.h"
#include <map>
#include <set>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ZeepSimulation");

enum MessageType {
    CAM_MSG = 1,
    KEY_REQUEST,
    KEY_RESPONSE
};

struct ZoneID {
    int x, y;
    
    // Existing less-than operator for ordering
    bool operator<(const ZoneID& other) const {
        return std::tie(x, y) < std::tie(other.x, other.y);
    }
    
    // Add equality operator
    bool operator==(const ZoneID& other) const {
        return x == other.x && y == other.y;
    }
    
    // Add inequality operator
    bool operator!=(const ZoneID& other) const {
        return !(*this == other);
    }
};

std::map<uint64_t, std::pair<Ipv4Address, Time>> g_packetRegistry;

// Custom Timestamp Tag Class
class CustomTimestampTag : public Tag {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("TimestampTag")
            .SetParent<Tag>()
            .AddConstructor<TimestampTag>()
            .AddAttribute("Timestamp",
                          "Timestamp when packet was sent",
                          EmptyAttributeValue(),
                          MakeTimeAccessor(&TimestampTag::GetTimestamp),
                          MakeTimeChecker());
        return tid;
    }

    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    
    uint32_t GetSerializedSize() const override { return 8; }
    
    void Serialize(TagBuffer i) const override {
        i.WriteU64(m_timestamp.GetNanoSeconds());
    }
    
    void Deserialize(TagBuffer i) override {
        m_timestamp = NanoSeconds(i.ReadU64());
    }
    
    void Print(std::ostream& os) const override {
        os << "Timestamp=" << m_timestamp;
    }

    Time GetTimestamp() const { return m_timestamp; }
    void SetTimestamp(Time time) { m_timestamp = time; }

private:
    Time m_timestamp;
};

// Constants
const double ZONE_SIZE = 200.0;
const Time KEY_REQUEST_DELAY = MilliSeconds(103.16);
const Time KEY_RESPONSE_DELAY = MilliSeconds(301.37);
const Time KEY_VERIFY_DELAY = MilliSeconds(193.86);
const Time CAM_INTERVAL = Seconds(10);
const Time ZONE_KEY_TIMEOUT = Seconds(1);
const Time ZONE_KEY_REFRESH = Minutes(15);

// Global metrics
uint32_t g_rxCount = 0;
uint32_t g_txCount = 0;
double g_totalLatency = 0.0;
uint32_t m_keyRequests = 0, m_keyResponses = 0;
double globalDelayedTime = 0;
double globalTotalZoneTime = 0;
// Global key generation counter
uint32_t g_isolatedKeyGenCount = 0; // Total inefficient generations
std::map<ZoneID, uint32_t> g_zoneKeyOwners; // Zone → number of vehicles with key
std::map<ZoneID, uint32_t> g_zoneKeyGenerations; // Zone → redundant key generations

class KeyMsgTag : public Tag {
public:
    enum MsgType { KEY_REQUEST = 1, KEY_RESPONSE = 2 };

    KeyMsgTag() : m_type(KEY_REQUEST), m_zoneX(0), m_zoneY(0) {}
    KeyMsgTag(MsgType type, int zoneX, int zoneY)
        : m_type(type), m_zoneX(zoneX), m_zoneY(zoneY) {}

    static TypeId GetTypeId() {
        static TypeId tid = TypeId("KeyMsgTag")
            .SetParent<Tag>()
            .AddConstructor<KeyMsgTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 12; }
    void Serialize(TagBuffer i) const override {
        i.WriteU32(static_cast<uint32_t>(m_type));
        i.WriteU32(static_cast<uint32_t>(m_zoneX));
        i.WriteU32(static_cast<uint32_t>(m_zoneY));
    }
    void Deserialize(TagBuffer i) override {
        m_type = static_cast<MsgType>(i.ReadU32());
        m_zoneX = static_cast<int>(i.ReadU32());
        m_zoneY = static_cast<int>(i.ReadU32());
    }
    void Print(std::ostream& os) const override {
        os << "KeyMsgTag(type=" << m_type << ", zone=(" << m_zoneX << "," << m_zoneY << "))";
    }

    void SetType(MsgType type) { m_type = type; }
    MsgType GetType() const { return m_type; }

    void SetZone(int x, int y) { m_zoneX = x; m_zoneY = y; }
    int GetZoneX() const { return m_zoneX; }
    int GetZoneY() const { return m_zoneY; }

private:
    MsgType m_type;
    int m_zoneX;
    int m_zoneY;
};

class VehicleApp : public Application {
public:
    VehicleApp() : m_socket(nullptr) {}
    void Setup(Ptr<Node> node, uint32_t id);
    void PrintMetrics();
    std::map<uint64_t, Time> m_sentPackets; // packetID → sendTime
    std::map<uint64_t, uint32_t> m_receivedPackets; // packetID → receiveCount
    uint64_t m_packetCounter = 0;
    std::map<ZoneID, Time> m_zoneEntryTimes;
    std::vector<Time> m_joinDelays;
    EventId m_currentZoneCheckEvent;
    const std::vector<Time>& GetJoinDelays() const { return m_joinDelays; }
    uint32_t m_totalZoneEntries = 0;
    uint32_t m_failedZoneJoins = 0;
    ZoneID m_previousZone = {-1, -1};
    bool m_currentZoneKeyAcquired = false;
    std::map<ZoneID, bool> m_zoneKeys;
    Ptr<Node> m_node;
    ZoneID m_currentZone;
        struct ZoneVisit {
        Time entryTime;
        Time exitTime;
        Time keyAcquiredTime;
        bool keyAcquired;
    };

    std::map<ZoneID, ZoneVisit> m_zoneVisits;  // Current and previous zone visits


private:
    virtual void StartApplication() override;
    virtual void StopApplication() override;

    void CheckZone();
    void SendKeyRequest();
    void ReceiveKeyResponse();
    void VerifyAndStoreKey();
    void GenerateOwnKey();
    void SendCAM();
    void ReceiveCAM(Ptr<Socket> socket);
    void RefreshZoneKey();
    void SendKeyResponse(const ZoneID& zone, const Address& to);

    Ptr<Socket> m_socket;
    uint32_t m_id;
    Ipv4Address m_address;
    std::map<ZoneID, EventId> m_keyTimers;
    uint32_t m_camSent = 0;
    uint32_t m_camReceived = 0;
    double m_totalLatency = 0.0;
    EventId m_camEvent;
    EventId m_checkZoneEvent;
};

void VehicleApp::Setup(Ptr<Node> node, uint32_t id) {
    m_id = id;
    m_node = node;
    m_socket = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    m_socket->SetAllowBroadcast(true); // Critical addition
    m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9));
    m_socket->SetRecvCallback(MakeCallback(&VehicleApp::ReceiveCAM, this));
    
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
    m_address = ipv4->GetAddress(1, 0).GetLocal();
}

void VehicleApp::StartApplication() {
    Simulator::Schedule(Seconds(1.0), &VehicleApp::CheckZone, this);
    m_camEvent = Simulator::Schedule(CAM_INTERVAL, &VehicleApp::SendCAM, this);
    Simulator::Schedule(ZONE_KEY_REFRESH, &VehicleApp::RefreshZoneKey, this);
}

void VehicleApp::StopApplication() {
    Simulator::Cancel(m_camEvent);
    Simulator::Cancel(m_checkZoneEvent);
    if (m_socket) m_socket->Close();
}

void VehicleApp::CheckZone() {
    // 1. Get current position and new zone
    Ptr<MobilityModel> mobility = m_node->GetObject<MobilityModel>();
    Vector pos = mobility->GetPosition();
    ZoneID newZone = {(int)(pos.x/ZONE_SIZE), (int)(pos.y/ZONE_SIZE)};

    // 2. Only act if zone has changed
    if (newZone != m_currentZone) {
        // 3. Finalize previous zone visit, if any
        if (m_currentZone.x != -1) {
            auto& visit = m_zoneVisits[m_currentZone];
            visit.exitTime = Simulator::Now();
            visit.keyAcquired = m_zoneKeys[m_currentZone];
            // Use last join delay for this zone if available
            if (!m_joinDelays.empty() && m_zoneEntryTimes.count(m_currentZone)) {
                visit.keyAcquiredTime = m_zoneEntryTimes[m_currentZone] + m_joinDelays.back();
            } else {
                visit.keyAcquiredTime = Time::Max();
            }

            // 4. Failure handling for previous zone
            if (!m_zoneKeys[m_currentZone]) {
                m_failedZoneJoins++;
                NS_LOG_INFO("Vehicle " << m_id << " failed to acquire key for Zone("
                            << m_currentZone.x << ", " << m_currentZone.y << ")");
            }

            // 5. Cancel any ongoing timers for previous zone
            auto oldTimer = m_keyTimers.find(m_currentZone);
            if (oldTimer != m_keyTimers.end()) {
                Simulator::Cancel(oldTimer->second);
                m_keyTimers.erase(oldTimer);
            }
        }

        // 6. Start new zone visit
        m_previousZone = m_currentZone;
        m_currentZone = newZone;
        m_totalZoneEntries++;

        m_zoneVisits[newZone].entryTime = Simulator::Now();
        m_zoneVisits[newZone].exitTime = Time::Max();  // Mark as ongoing

        // Store precise entry time for this zone instance
        m_zoneEntryTimes[newZone] = Simulator::Now();

        // 7. Start new key acquisition process if needed
        if (m_zoneKeys.find(newZone) == m_zoneKeys.end()) {
            m_currentZoneKeyAcquired = false;
            SendKeyRequest();
            m_keyTimers[newZone] = Simulator::Schedule(
                ZONE_KEY_TIMEOUT, &VehicleApp::GenerateOwnKey, this);
        } else {
            m_currentZoneKeyAcquired = true;
        }
    }

    // 8. Recheck zone position with 100ms resolution
    m_currentZoneCheckEvent = Simulator::Schedule(MilliSeconds(100),
        &VehicleApp::CheckZone, this);
}


void VehicleApp::SendKeyRequest() {
    // Builds a packet with a message type tag and zone info
    Ptr<Packet> packet = Create<Packet>(8); 

    // Adds message type as a tag
    KeyMsgTag tag(KeyMsgTag::KEY_REQUEST, m_currentZone.x, m_currentZone.y);
    packet->AddByteTag(tag);


    m_socket->SendTo(packet, 0, InetSocketAddress(Ipv4Address("255.255.255.255"), 9));
    m_keyRequests++;
    // Starting timer to wait for response
    m_keyTimers[m_currentZone] = Simulator::Schedule(ZONE_KEY_TIMEOUT, &VehicleApp::GenerateOwnKey, this);
}

void VehicleApp::SendKeyResponse(const ZoneID& zone, const Address& to) {
    Ptr<Packet> packet = Create<Packet>(8); 

    KeyMsgTag tag(KeyMsgTag::KEY_RESPONSE, zone.x, zone.y);
    packet->AddByteTag(tag);

    m_socket->SendTo(packet, 0, to);   
    m_keyResponses++;
}

void VehicleApp::VerifyAndStoreKey() {
    m_currentZoneKeyAcquired = true;
    Time acquisitionTime = Simulator::Now();
    Time delay = acquisitionTime - m_zoneEntryTimes[m_currentZone];
    
    if (delay > Seconds(0)) {
        m_joinDelays.push_back(delay);
        NS_LOG_INFO("Vehicle " << m_id << " zone(" 
            << m_currentZone.x << "," << m_currentZone.y 
            << ") secure join delay: " << delay.GetMilliSeconds() << "ms");
    }
    
    // Tracks this vehicle's ownership of the key
    g_zoneKeyOwners[m_currentZone]++;
    m_zoneKeys[m_currentZone] = true;
    Simulator::Cancel(m_keyTimers[m_currentZone]);
}

void VehicleApp::GenerateOwnKey() {
    m_currentZoneKeyAcquired = true;
    Time acquisitionTime = Simulator::Now();
    Time delay = acquisitionTime - m_zoneEntryTimes[m_currentZone];
    
    m_joinDelays.push_back(delay);
    NS_LOG_WARN("Vehicle " << m_id << " zone(" 
        << m_currentZone.x << "," << m_currentZone.y 
        << ") timeout delay: " << delay.GetMilliSeconds() << "ms");

    // Only counts as inefficient if another vehicle already has the key
    if (g_zoneKeyOwners[m_currentZone] > 0) {
        g_zoneKeyGenerations[m_currentZone]++;
    }
    
    // Tracks this vehicle's ownership of the key
    g_zoneKeyOwners[m_currentZone]++;
    m_zoneKeys[m_currentZone] = true;
}


void VehicleApp::SendCAM() {
    for (auto& [zone, hasKey] : m_zoneKeys) {
        if (hasKey) {
            Ptr<Packet> packet = Create<Packet>(100);
            
            CustomTimestampTag txTimeTag;
            txTimeTag.SetTimestamp(Simulator::Now());
            packet->AddByteTag(txTimeTag);
            
            m_socket->SendTo(packet, 0, 
                InetSocketAddress(Ipv4Address("255.255.255.255"), 9));
            
            m_camSent++;
            g_txCount++;
        }
    }
    m_camEvent = Simulator::Schedule(CAM_INTERVAL, &VehicleApp::SendCAM, this);
    NS_LOG_UNCOND("Vehicle " << m_id << " sent CAM at " << Simulator::Now());
}

/*
void VehicleApp::ReceiveCAM(Ptr<Socket> socket) {
  Ptr<Packet> packet;
  Address from;
  while ((packet = socket->RecvFrom(from))) {
      // Use ByteTagIterator to access byte tags
      ByteTagIterator it = packet->GetByteTagIterator();
      
      while (it.HasNext()) {
          ByteTagIterator::Item item = it.Next();
          if (item.GetTypeId() == CustomTimestampTag::GetTypeId()) {
              CustomTimestampTag rxTag;
              item.GetTag(rxTag);
              Time latency = Simulator::Now() - rxTag.GetTimestamp();
              m_totalLatency += latency.GetMilliSeconds();
              g_totalLatency += latency.GetMilliSeconds();
              m_camReceived++;
              g_rxCount++;
          }
      }
  }
  NS_LOG_UNCOND("Vehicle " << m_id << " received CAM at " << Simulator::Now());
}
  */

void VehicleApp::ReceiveCAM(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from))) {
        ByteTagIterator it = packet->GetByteTagIterator();
        bool handledControl = false;
        bool handledCAM = false;

        while (it.HasNext()) {
            ByteTagIterator::Item item = it.Next();
            
            // Handles Key Management Control Messages
            if (item.GetTypeId() == KeyMsgTag::GetTypeId()) {
                KeyMsgTag tag;
                item.GetTag(tag);
                handledControl = true;

                if (tag.GetType() == KeyMsgTag::KEY_REQUEST) {
                    ZoneID reqZone = {tag.GetZoneX(), tag.GetZoneY()};
                    NS_LOG_INFO("Vehicle " << m_id << " received KEY_REQUEST for Zone(" 
                                << reqZone.x << "," << reqZone.y << ")");
                    
                    // Checks if we have valid key for requested zone
                    if (m_zoneKeys.count(reqZone) && m_zoneKeys[reqZone]) {
                        NS_LOG_INFO("Vehicle " << m_id << " responding with KEY_RESPONSE");
                        SendKeyResponse(reqZone, from);
                    }
                }
                else if (tag.GetType() == KeyMsgTag::KEY_RESPONSE) {
                    ZoneID respZone = {tag.GetZoneX(), tag.GetZoneY()};
                    NS_LOG_INFO("Vehicle " << m_id << " received KEY_RESPONSE for Zone(" 
                                << respZone.x << "," << respZone.y << ")");
                    
                    // Only process if response matches current zone and key not acquired
                    if (respZone == m_currentZone && !m_currentZoneKeyAcquired) {
                        NS_LOG_INFO("Vehicle " << m_id << " accepting zone key");
                        Simulator::Cancel(m_keyTimers[m_currentZone]);
                        VerifyAndStoreKey();
                    }
                }
            }
            // Handles CAM Message Metrics
            else if (item.GetTypeId() == CustomTimestampTag::GetTypeId()) {
                CustomTimestampTag rxTag;
                item.GetTag(rxTag);
                Time latency = Simulator::Now() - rxTag.GetTimestamp();
                
                // Updates metrics
                m_totalLatency += latency.GetMilliSeconds();
                g_totalLatency += latency.GetMilliSeconds();
                m_camReceived++;
                g_rxCount++;
                
                handledCAM = true;
                NS_LOG_UNCOND("Vehicle " << m_id << " processed CAM with latency " 
                              << latency.GetMilliSeconds() << "ms");
            }
        }

        // Logs packet reception (control or CAM)
        if (handledControl || handledCAM) {
            NS_LOG_DEBUG("Vehicle " << m_id << " handled " 
                          << (handledControl ? "control" : "CAM") 
                          << " packet from " << InetSocketAddress::ConvertFrom(from).GetIpv4());
        }
    }
}

void VehicleApp::RefreshZoneKey() {
    // Removes this vehicle's ownership of all keys
    for (const auto& [zone, hasKey] : m_zoneKeys) {
        if (hasKey) {
            if (g_zoneKeyOwners[zone] > 0) {
                g_zoneKeyOwners[zone]--;
            }
        }
    }
    m_zoneKeys.clear();
    
    Simulator::Schedule(ZONE_KEY_REFRESH, &VehicleApp::RefreshZoneKey, this);
}


void VehicleApp::PrintMetrics() {
    double pdr = (m_camSent > 0) ? (double)m_camReceived/m_camSent : 0;
    double avgLatency = (m_camReceived > 0) ? m_totalLatency/m_camReceived : 0;
    
    NS_LOG_UNCOND("Vehicle " << m_id << " | PDR: " << pdr 
                  << " | Avg Latency: " << avgLatency << " ms");
                  
    double avgDelay = 0;
    Time maxDelay(0);
    if (!m_joinDelays.empty()) {
        for (const auto& delay : m_joinDelays) {
            avgDelay += delay.GetMilliSeconds();
            if (delay > maxDelay) maxDelay = delay;
        }
        avgDelay /= m_joinDelays.size();
    }
    
    NS_LOG_UNCOND("Vehicle " << m_id 
        << " | Avg Join Delay: " << avgDelay << "ms"
        << " | Max Join Delay: " << maxDelay.GetMilliSeconds() << "ms");

    double failureRate = (m_totalZoneEntries > 0) ?
    (static_cast<double>(m_failedZoneJoins) / m_totalZoneEntries) * 100 : 0;
        
    NS_LOG_UNCOND("Vehicle " << m_id 
        << " | Zone Join Failures: " << m_failedZoneJoins
        << "/" << m_totalZoneEntries
        << " (" << failureRate << "%)");

     // Zone residence analysis
    double totalDelayedTime = 0;
    double totalZoneTime = 0;
    
    for (const auto& [zone, visit] : m_zoneVisits) {
        if (visit.exitTime == Time::Max()) continue;  // Skips ongoing visits
        
        Time residence = visit.exitTime - visit.entryTime;
        Time delayed;
        if (visit.keyAcquired && visit.keyAcquiredTime < visit.exitTime) {
            delayed = visit.keyAcquiredTime - visit.entryTime;
        } else {
            delayed = residence;
        }
        
        totalDelayedTime += delayed.GetSeconds();
        totalZoneTime += residence.GetSeconds();
    }

    NS_LOG_UNCOND("Vehicle " << m_id << " | Delayed/Total Zone Time Ratio: " 
                  << (totalZoneTime > 0 ? totalDelayedTime/totalZoneTime : 0));
}

int main(int argc, char *argv[]) {
    uint32_t numVehicles = 50;
    double simTime = 100.0;
    double areaSize = 10000.0;
    
    CommandLine cmd;
    cmd.AddValue("numVehicles", "Number of vehicles", numVehicles);
    cmd.Parse(argc, argv);

    Config::SetDefault("ns3::WifiPhy::CcaEdThreshold", DoubleValue(-62.0)); 
    Config::SetDefault("ns3::WifiPhy::TxGain", DoubleValue(2.0));  
    Config::SetDefault("ns3::WifiPhy::RxNoiseFigure", DoubleValue(7.0)); 

    // Configure Wifi
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
        "DataMode", StringValue("OfdmRate6MbpsBW10MHz"),
        "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"));

    YansWifiChannelHelper channel;
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::RangePropagationLossModel",
                              "MaxRange", DoubleValue(400.0));
    
    YansWifiPhyHelper phy;
    phy.Set("RxNoiseFigure", DoubleValue(7.0));
    phy.Set("TxPowerStart", DoubleValue(23.0));
    phy.Set("TxPowerEnd", DoubleValue(23.0));
    
    // Configure error model
    Ptr<RateErrorModel> pem = CreateObject<RateErrorModel>();
    pem->SetAttribute("ErrorRate", DoubleValue(0.01));
    pem->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
    phy.Set("PostReceptionErrorModel", PointerValue(pem));
    
    phy.SetChannel(channel.Create());
                              

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    NodeContainer vehicles;
    vehicles.Create(numVehicles);

    // Configure mobility model
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::WaypointMobilityModel");
    mobility.SetPositionAllocator("ns3::RandomRectanglePositionAllocator",
        "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(areaSize) + "]"),
        "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(areaSize) + "]"));
    mobility.Install(vehicles);

    // Configure waypoints
    Ptr<UniformRandomVariable> speedRng = CreateObject<UniformRandomVariable>();
    speedRng->SetAttribute("Min", DoubleValue(10.0));
    speedRng->SetAttribute("Max", DoubleValue(15.0));
    
    for (uint32_t i = 0; i < vehicles.GetN(); ++i) {
        Ptr<Node> node = vehicles.Get(i);
        Ptr<WaypointMobilityModel> mob = node->GetObject<WaypointMobilityModel>();
        
        if (!mob) {
            NS_FATAL_ERROR("Failed to get WaypointMobilityModel for node " << i);
        }

        Vector initialPos = node->GetObject<MobilityModel>()->GetPosition();
        double speed = speedRng->GetValue();
        double travelTime = 1500.0 / speed;

        mob->AddWaypoint(Waypoint(Seconds(0), initialPos));
        mob->AddWaypoint(Waypoint(Seconds(travelTime), 
            Vector(initialPos.x + 1500, initialPos.y, 0)));
    }


    NetDeviceContainer devices = wifi.Install(phy, mac, vehicles);
    InternetStackHelper internet;
    internet.Install(vehicles);
    
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    ipv4.Assign(devices);

    for (uint32_t i = 0; i < vehicles.GetN(); ++i) {
        Ptr<VehicleApp> app = CreateObject<VehicleApp>();
        app->Setup(vehicles.Get(i), i);
        vehicles.Get(i)->AddApplication(app);
        app->SetStartTime(Seconds(0));
        app->SetStopTime(Seconds(simTime));

        Ptr<MobilityModel> mob = vehicles.Get(i)->GetObject<MobilityModel>();
        Vector pos = mob->GetPosition();
        ZoneID initialZone = {(int)(pos.x / ZONE_SIZE), (int)(pos.y / ZONE_SIZE)};
        app->m_zoneKeys[initialZone] = true;
        app->m_currentZone = initialZone;
        app->m_currentZoneKeyAcquired = true;
    }

    Simulator::Schedule(Seconds(simTime), [&vehicles]() {
        for (uint32_t i = 0; i < vehicles.GetN(); ++i) {
            Ptr<VehicleApp> app = vehicles.Get(i)->GetApplication(0)->GetObject<VehicleApp>();
            if (app) app->PrintMetrics();
        }
        
        double globalPDR = (g_txCount > 0) ? (double)g_rxCount/g_txCount : 0;
        double globalLatency = (g_rxCount > 0) ? g_totalLatency/g_rxCount : 0;
        
        NS_LOG_UNCOND("\nGlobal Metrics:");
        NS_LOG_UNCOND("Total CAMs Sent: " << g_txCount);
        NS_LOG_UNCOND("Total CAMs Received: " << g_rxCount);
        NS_LOG_UNCOND("Network PDR: " << globalPDR);
        NS_LOG_UNCOND("Average Latency: " << globalLatency << " ms");

        double globalAvg = 0;
        Time globalMax(0);
        uint32_t totalMeasurements = 0;
        
        for (uint32_t i = 0; i < vehicles.GetN(); ++i) {
            Ptr<VehicleApp> app = vehicles.Get(i)->GetApplication(0)->GetObject<VehicleApp>();
            auto delays = app->GetJoinDelays(); // Add getter method
            
            for (const auto& delay : delays) {
                globalAvg += delay.GetMilliSeconds();
                if (delay > globalMax) globalMax = delay;
                totalMeasurements++;
            }
        }
        
        if (totalMeasurements > 0) {
            globalAvg /= totalMeasurements;
            NS_LOG_UNCOND("\nGlobal Join Delay Metrics:");
            NS_LOG_UNCOND("Average: " << globalAvg << "ms");
        }

        uint32_t totalFailures = 0;
        uint32_t totalEntries = 0;

        for (uint32_t i = 0; i < vehicles.GetN(); ++i) {
            Ptr<VehicleApp> app = vehicles.Get(i)->GetApplication(0)->GetObject<VehicleApp>();
            if (app) {
                totalFailures += app->m_failedZoneJoins;
                totalEntries += app->m_totalZoneEntries;
            }
        }

        double globalFailureRate = (totalEntries > 0) ?
            (static_cast<double>(totalFailures) / totalEntries) * 100 : 0;

        NS_LOG_UNCOND("\nGlobal Zone Join Metrics:");
        NS_LOG_UNCOND("Total Zone Entries: " << totalEntries);
        NS_LOG_UNCOND("Failed Joins: " << totalFailures);
        NS_LOG_UNCOND("Failure Rate: " << globalFailureRate << "%");

        uint32_t totalControlMessages = m_keyRequests + m_keyResponses;
        double controlToDataRatio = (g_txCount > 0) ? (double)totalControlMessages / g_txCount : 0;

        NS_LOG_UNCOND("\nControl-to-Data Message Ratio:");
        NS_LOG_UNCOND("Total Control Messages: " << totalControlMessages
            << " (Requests: " << m_keyRequests
            << ", Responses: " << m_keyResponses << ")");
        NS_LOG_UNCOND("Total CAMs Sent: " << g_txCount);
        NS_LOG_UNCOND("Control-to-Data Ratio: " << controlToDataRatio);

        for (uint32_t i = 0; i < vehicles.GetN(); ++i) {
            Ptr<VehicleApp> app = vehicles.Get(i)->GetApplication(0)->GetObject<VehicleApp>();
            for (const auto& [zone, visit] : app->m_zoneVisits) {
                if (visit.exitTime == Time::Max()) continue;
                
                Time residence = visit.exitTime - visit.entryTime;
                Time delayed;
                if (visit.keyAcquired && visit.keyAcquiredTime < visit.exitTime) {
                    delayed = visit.keyAcquiredTime - visit.entryTime;
                } else {
                    delayed = residence;
                }

                
                globalDelayedTime += delayed.GetSeconds();
                globalTotalZoneTime += residence.GetSeconds();
            }
        }

        NS_LOG_UNCOND("\nGlobal Delayed Join Impact:");
        NS_LOG_UNCOND("Total Delayed Time: " << globalDelayedTime << "s");
        NS_LOG_UNCOND("Total Zone Residence Time: " << globalTotalZoneTime << "s");
        NS_LOG_UNCOND("Ratio: " << (globalTotalZoneTime > 0 ? globalDelayedTime/globalTotalZoneTime : 0));

        uint32_t totalKeyGenerations = 0;
        uint32_t inefficientKeyGenerations = 0;
        uint32_t zonesWithDuplicates = 0;

        for (const auto& [zone, count] : g_zoneKeyGenerations) {
            totalKeyGenerations += count;
            if (count > 1) {
                inefficientKeyGenerations += (count - 1);
                zonesWithDuplicates++;
            }
        }

        NS_LOG_UNCOND("\nIsolated Zone Key Generation Metrics:");
        NS_LOG_UNCOND("Total Key Generations: " << totalKeyGenerations);
        NS_LOG_UNCOND("Total Zones with Duplicate Keys: " << zonesWithDuplicates);
        NS_LOG_UNCOND("Inefficient Key Generations: " << inefficientKeyGenerations);
        NS_LOG_UNCOND("Fraction Inefficient: " 
            << (totalKeyGenerations > 0 ? double(inefficientKeyGenerations) / totalKeyGenerations : 0));


    });

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();
    
    return 0;
}
