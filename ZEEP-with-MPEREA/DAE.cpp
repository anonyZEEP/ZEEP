#include "DAE.h"

using namespace CryptoPP;
using byte = unsigned char;
DAE::DAE(){

}
std::pair<byte *, byte*> DAE::KeyGen(int key_size, int block_size, int tag_size){
    this->TAG_LEN = tag_size;
    this->KEY_LEN = key_size;
    this->IV_LEN = block_size;

    AutoSeededRandomPool prng;
    byte *key = new byte[key_size];
    prng.GenerateBlock(key, key_size);

    byte *iv = new byte[block_size];
	prng.GenerateBlock(iv, block_size);

    return std::make_pair(key, iv);

}
std::pair<byte*, size_t> DAE::Encrypt(byte* key, byte* iv, std::string msg){

    try
    {
        GCM< AES >::Encryption e;
        e.SetKeyWithIV( key, KEY_LEN, iv, IV_LEN);
        // Not required for GCM mode (but required for CCM mode)
        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );
        std::string cipher; 
        AuthenticatedEncryptionFilter ef( e,
            new StringSink( cipher ), false, TAG_LEN
        ); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        // ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
        // ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut( "", (const byte*)msg.data(), msg.size() );
        ef.ChannelMessageEnd("");

        // Pretty print
        StringSource( cipher, true,
            new HexEncoder( new StringSink( encoded ), true, 16, " " ) );
        //cout<<encoded;
    }
    catch( CryptoPP::BufferedTransformation::NoChannelSupport& e )
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

}
DAE::Decrypt(){
     try
    {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV( key, KEY_LEN, iv, IV_LEN);

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr( 0, cipher.length()-TAG_LEN );
        string mac = cipher.substr( cipher.length()-TAG_LEN );
        cout<<mac<<endl;

        // Sanity checks
        assert( cipher.size() == enc.size() + mac.size() );
        assert( enc.size() == pdata.size() );
        assert( TAG_SIZE == mac.size() );

        // Not recovered - sent via clear channel
        radata = adata;     

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

        // The order of the following calls are important
        df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
        //df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
        df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        //df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert( true == b );

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        rpdata = retrieved;
        assert( rpdata == pdata );

        // Hmmm... No way to get the calculated MAC
        //  mac out of the Decryptor/Verifier. At
        //  least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == mac );

        // All is well - work with data
        cout << "Decrypted and Verified data. Ready for use." << endl;
        cout << endl;

       // cout << "adata length: " << adata.size() << endl;
        cout << "pdata length: " << pdata.size() << endl;
        cout << endl;

        //cout << "adata: " << adata << endl;
        cout << "pdata: " << pdata << endl;
        //cout << endl;

        cout << "cipher text: " << endl << " " << encoded << endl;
        cout << endl;

        //cout << "recovered adata length: " << radata.size() << endl;
        cout << "recovered pdata length: " << rpdata.size() << endl;
        cout << endl;

        //cout << "recovered adata: " << radata << endl;
        cout << "recovered pdata: " << rpdata << endl;
        //cout << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

}