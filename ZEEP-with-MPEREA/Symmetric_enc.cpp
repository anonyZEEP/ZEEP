#include "Symmetric_enc.h"

Symmetric_enc::Symmetric_enc(){

}

std::pair<byte *, byte*> Symmetric_enc::KeyGen(int key_length, int block_size){
    
    AutoSeededRandomPool prng;
    byte *key = new byte[key_length];
    prng.GenerateBlock(key, key_length);

    byte *iv = new byte[block_size];
	prng.GenerateBlock(iv, block_size);

    return std::make_pair(key, iv);
}
std::pair<byte*, size_t> Symmetric_enc::Encrypt_payload(byte* key, byte* iv, std::string msg){
    // string plain = "CTR Mode Test";
	// string cipher, encoded, recovered;
    std::string encoded;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, AES::DEFAULT_KEYLENGTH, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	//std::cout << "key: " << encoded << std::endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, AES::BLOCKSIZE, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	//std::cout << "iv: " << encoded << std::endl;

	/*********************************\
	\*********************************/
    std::string cipher;
	try
	{
		//std::cout << "plain text: " << msg << std::endl;

		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(msg, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/
    
	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	//std::cout << "cipher text: " << encoded << std::endl;

    size_t size = msg.size();
    byte *ans = new byte[cipher.size()];
    std::copy( cipher.begin(), cipher.end(), ans);
    ans[cipher.length()] = 0;
    cipher.clear();
    return std::make_pair(ans, size); 
    
}
std::pair<byte*, size_t> Symmetric_enc::Decrypt_payload(byte* key, byte* iv, std::string cipher){
    std::string msg;
    try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

		// The StreamTransformationFilter removes
		//  padding as required.
        
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(msg)
			) // StreamTransformationFilter
		); // StringSource

		//std::cout << "recovered text: " << msg << std::endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
    size_t size = msg.size();
    byte *ans = new byte[msg.size()];
    std::copy( msg.begin(), msg.end(), ans);
    msg.clear();

    return std::make_pair(ans, size);


}