#ifndef CRYPTOPPUTIL_H
#define CRYPTOPPUTIL_H

#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "dll.h"
#include "cryptlib.h"
#include "aes.h"
#include "filters.h"
#include "md5.h"
#include "ripemd.h"
#include "rng.h"
#include "gzip.h"
#include "default.h"
#include "randpool.h"
#include "ida.h"
#include "base64.h"
#include "factory.h"
#include "whrlpool.h"
#include "tiger.h"
#include "smartptr.h"
#include "pkcspad.h"
#include "stdcpp.h"
#include "osrng.h"
#include "ossig.h"
#include "trap.h"

#include "validate.h"
#include "bench.h"

#include <iostream>
#include <sstream>
#include <locale>
#include <cstdlib>
#include <ctime>

#ifdef CRYPTOPP_WIN32_AVAILABLE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#if defined(CRYPTOPP_UNIX_AVAILABLE) || defined(CRYPTOPP_BSD_AVAILABLE)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define UNIX_PATH_FAMILY 1
#endif

#if defined(CRYPTOPP_OSX_AVAILABLE)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#define UNIX_PATH_FAMILY 1
#endif

#if (_MSC_VER >= 1000)
#include <crtdbg.h>		// for the debug heap
#endif

#if defined(__MWERKS__) && defined(macintosh)
#include <console.h>
#endif

#ifdef _OPENMP
# include <omp.h>
#endif

#ifdef __BORLANDC__
#pragma comment(lib, "cryptlib_bds.lib")
#endif

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

NAMESPACE_BEGIN(CryptoPP)
class CryptoppAPI
{
public:
    #if (CRYPTOPP_USE_AES_GENERATOR)
    OFB_Mode<AES>::Encryption s_globalRNG;
    #else
    NonblockingRng s_globalRNG;
    #endif

    RandomNumberGenerator & GlobalRNG()
    {
        return dynamic_cast<RandomNumberGenerator&>(s_globalRNG);
    }

    SecByteBlock HexDecodeString(const char *hex)
    {
        StringSource ss(hex, true, new HexDecoder);
        SecByteBlock result((size_t)ss.MaxRetrievable());
        ss.Get(result, result.size());
        return result;
    }

    void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
    {
        // DEREncode() changed to Save() at Issue 569.
        RandomPool randPool;
        randPool.IncorporateEntropy((byte *)seed, strlen(seed));

        RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
        HexEncoder privFile(new FileSink(privFilename));
        priv.AccessMaterial().Save(privFile);
        privFile.MessageEnd();

        RSAES_OAEP_SHA_Encryptor pub(priv);
        HexEncoder pubFile(new FileSink(pubFilename));
        pub.AccessMaterial().Save(pubFile);
        pubFile.MessageEnd();
    }

    std::string RSAEncryptString(const char *pubFilename, const char *seed, const char *message)
    {
        FileSource pubFile(pubFilename, true, new HexDecoder);
        RSAES_OAEP_SHA_Encryptor pub(pubFile);

        RandomPool randPool;
        randPool.IncorporateEntropy((byte *)seed, strlen(seed));

        std::string result;
        StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
        return result;
    }

    std::string RSADecryptString(const char *privFilename, const char *ciphertext)
    {
        FileSource privFile(privFilename, true, new HexDecoder);
        RSAES_OAEP_SHA_Decryptor priv(privFile);

        std::string result;
        StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
        return result;
    }

    void RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename)
    {
        FileSource privFile(privFilename, true, new HexDecoder);
        RSASS<PKCS1v15, SHA1>::Signer priv(privFile);
        FileSource f(messageFilename, true, new SignerFilter(GlobalRNG(), priv, new HexEncoder(new FileSink(signatureFilename))));
    }

    bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename)
    {
        FileSource pubFile(pubFilename, true, new HexDecoder);
        RSASS<PKCS1v15, SHA1>::Verifier pub(pubFile);

        FileSource signatureFile(signatureFilename, true, new HexDecoder);
        if (signatureFile.MaxRetrievable() != pub.SignatureLength())
            return false;
        SecByteBlock signature(pub.SignatureLength());
        signatureFile.Get(signature, signature.size());

        SignatureVerificationFilter *verifierFilter = new SignatureVerificationFilter(pub);
        verifierFilter->Put(signature, pub.SignatureLength());
        FileSource f(messageFilename, true, verifierFilter);

        return verifierFilter->GetLastResult();
    }

    void DigestFile(const char *filename)
    {
        SHA1 sha;
        RIPEMD160 ripemd;
        SHA256 sha256;
        Tiger tiger;
        SHA512 sha512;
        Whirlpool whirlpool;

        vector_member_ptrs<HashFilter> filters(6);
        filters[0].reset(new HashFilter(sha));
        filters[1].reset(new HashFilter(ripemd));
        filters[2].reset(new HashFilter(tiger));
        filters[3].reset(new HashFilter(sha256));
        filters[4].reset(new HashFilter(sha512));
        filters[5].reset(new HashFilter(whirlpool));

        member_ptr<ChannelSwitch> channelSwitch(new ChannelSwitch);
        size_t i;
        for (i=0; i<filters.size(); i++)
            channelSwitch->AddDefaultRoute(*filters[i]);
        FileSource(filename, true, channelSwitch.release());

        HexEncoder encoder(new FileSink(std::cout), false);
        for (i=0; i<filters.size(); i++)
        {
            std::cout << filters[i]->AlgorithmName() << ": ";
            filters[i]->TransferTo(encoder);
            std::cout << "\n";
        }
    }

    void HmacFile(const char *hexKey, const char *file)
    {
        member_ptr<MessageAuthenticationCode> mac;
        if (strcmp(hexKey, "selftest") == 0)
        {
            std::cerr << "Computing HMAC/SHA1 value for self test.\n";
            mac.reset(NewIntegrityCheckingMAC());
        }
        else
        {
            std::string decodedKey;
            StringSource(hexKey, true, new HexDecoder(new StringSink(decodedKey)));
            mac.reset(new HMAC<SHA1>((const byte *)decodedKey.data(), decodedKey.size()));
        }
        FileSource(file, true, new HashFilter(*mac, new HexEncoder(new FileSink(std::cout))));
    }

    void AES_CTR_Encrypt(const char *hexKey, const char *hexIV, const char *infile, const char *outfile)
    {
        SecByteBlock key = HexDecodeString(hexKey);
        SecByteBlock iv = HexDecodeString(hexIV);
        CTR_Mode<AES>::Encryption aes(key, key.size(), iv);
        FileSource(infile, true, new StreamTransformationFilter(aes, new FileSink(outfile)));
    }

    std::string EncryptString(const char *instr, const char *passPhrase)
    {
        std::string outstr;

        DefaultEncryptorWithMAC encryptor(passPhrase, new HexEncoder(new StringSink(outstr)));
        encryptor.Put((byte *)instr, strlen(instr));
        encryptor.MessageEnd();

        return outstr;
    }

    std::string DecryptString(const char *instr, const char *passPhrase)
    {
        std::string outstr;

        HexDecoder decryptor(new DefaultDecryptorWithMAC(passPhrase, new StringSink(outstr)));
        decryptor.Put((byte *)instr, strlen(instr));
        decryptor.MessageEnd();

        return outstr;
    }

    void EncryptFile(const char *in, const char *out, const char *passPhrase)
    {
        FileSource f(in, true, new DefaultEncryptorWithMAC(passPhrase, new FileSink(out)));
    }

    void DecryptFile(const char *in, const char *out, const char *passPhrase)
    {
        FileSource f(in, true, new DefaultDecryptorWithMAC(passPhrase, new FileSink(out)));
    }

    void SecretShareFile(int threshold, int nShares, const char *filename, const char *seed)
    {
        CRYPTOPP_ASSERT(nShares >= 1 && nShares<=1000);
        if (nShares < 1 || nShares > 1000)
            throw InvalidArgument("SecretShareFile: " + IntToString(nShares) + " is not in range [1, 1000]");

        RandomPool rng;
        rng.IncorporateEntropy((byte *)seed, strlen(seed));

        ChannelSwitch *channelSwitch = NULLPTR;
        FileSource source(filename, false, new SecretSharing(rng, threshold, nShares, channelSwitch = new ChannelSwitch));

        // Be careful of the type of Sink used. An ArraySink will stop writing data once the array
        //    is full. Also see http://groups.google.com/forum/#!topic/cryptopp-users/XEKKLCEFH3Y.
        vector_member_ptrs<FileSink> fileSinks(nShares);
        std::string channel;
        for (int i=0; i<nShares; i++)
        {
            char extension[5] = ".000";
            extension[1]='0'+byte(i/100);
            extension[2]='0'+byte((i/10)%10);
            extension[3]='0'+byte(i%10);
            fileSinks[i].reset(new FileSink((std::string(filename)+extension).c_str()));

            channel = WordToString<word32>(i);
            fileSinks[i]->Put((const byte *)channel.data(), 4);
            channelSwitch->AddRoute(channel, *fileSinks[i], DEFAULT_CHANNEL);
        }

        source.PumpAll();
    }

    void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
    {
        CRYPTOPP_ASSERT(threshold >= 1 && threshold <=1000);
        if (threshold < 1 || threshold > 1000)
            throw InvalidArgument("SecretRecoverFile: " + IntToString(threshold) + " is not in range [1, 1000]");

        SecretRecovery recovery(threshold, new FileSink(outFilename));

        vector_member_ptrs<FileSource> fileSources(threshold);
        SecByteBlock channel(4);
        int i;
        for (i=0; i<threshold; i++)
        {
            fileSources[i].reset(new FileSource(inFilenames[i], false));
            fileSources[i]->Pump(4);
            fileSources[i]->Get(channel, 4);
            fileSources[i]->Attach(new ChannelSwitch(recovery, std::string((char *)channel.begin(), 4)));
        }

        while (fileSources[0]->Pump(256))
            for (i=1; i<threshold; i++)
                fileSources[i]->Pump(256);

        for (i=0; i<threshold; i++)
            fileSources[i]->PumpAll();
    }

    void InformationDisperseFile(int threshold, int nShares, const char *filename)
    {
        CRYPTOPP_ASSERT(threshold >= 1 && threshold <=1000);
        if (threshold < 1 || threshold > 1000)
            throw InvalidArgument("InformationDisperseFile: " + IntToString(nShares) + " is not in range [1, 1000]");

        ChannelSwitch *channelSwitch = NULLPTR;
        FileSource source(filename, false, new InformationDispersal(threshold, nShares, channelSwitch = new ChannelSwitch));

        // Be careful of the type of Sink used. An ArraySink will stop writing data once the array
        //    is full. Also see http://groups.google.com/forum/#!topic/cryptopp-users/XEKKLCEFH3Y.
        vector_member_ptrs<FileSink> fileSinks(nShares);
        std::string channel;
        for (int i=0; i<nShares; i++)
        {
            char extension[5] = ".000";
            extension[1]='0'+byte(i/100);
            extension[2]='0'+byte((i/10)%10);
            extension[3]='0'+byte(i%10);
            fileSinks[i].reset(new FileSink((std::string(filename)+extension).c_str()));

            channel = WordToString<word32>(i);
            fileSinks[i]->Put((const byte *)channel.data(), 4);
            channelSwitch->AddRoute(channel, *fileSinks[i], DEFAULT_CHANNEL);
        }

        source.PumpAll();
    }

    void InformationRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
    {
        CRYPTOPP_ASSERT(threshold<=1000);
        if (threshold < 1 || threshold > 1000)
            throw InvalidArgument("InformationRecoverFile: " + IntToString(threshold) + " is not in range [1, 1000]");

        InformationRecovery recovery(threshold, new FileSink(outFilename));

        vector_member_ptrs<FileSource> fileSources(threshold);
        SecByteBlock channel(4);
        int i;
        for (i=0; i<threshold; i++)
        {
            fileSources[i].reset(new FileSource(inFilenames[i], false));
            fileSources[i]->Pump(4);
            fileSources[i]->Get(channel, 4);
            fileSources[i]->Attach(new ChannelSwitch(recovery, std::string((char *)channel.begin(), 4)));
        }

        while (fileSources[0]->Pump(256))
            for (i=1; i<threshold; i++)
                fileSources[i]->Pump(256);

        for (i=0; i<threshold; i++)
            fileSources[i]->PumpAll();
    }

    void GzipFile(const char *in, const char *out, int deflate_level)
    {
    //	FileSource(in, true, new Gzip(new FileSink(out), deflate_level));

        // use a filter graph to compare decompressed data with original
        //
        // Source ----> Gzip ------> Sink
        //    \           |
        //	    \       Gunzip
        //		  \       |
        //		    \     v
        //		      > ComparisonFilter

        EqualityComparisonFilter comparison;

        Gunzip gunzip(new ChannelSwitch(comparison, "0"));
        gunzip.SetAutoSignalPropagation(0);

        FileSink sink(out);

        ChannelSwitch *cs;
        Gzip gzip(cs = new ChannelSwitch(sink), deflate_level);
        cs->AddDefaultRoute(gunzip);

        cs = new ChannelSwitch(gzip);
        cs->AddDefaultRoute(comparison, "1");
        FileSource source(in, true, cs);

        comparison.ChannelMessageSeriesEnd("0");
        comparison.ChannelMessageSeriesEnd("1");
    }

    void GunzipFile(const char *in, const char *out)
    {
        FileSource(in, true, new Gunzip(new FileSink(out)));
    }

    void Base64Encode(const char *in, const char *out)
    {
        FileSource(in, true, new Base64Encoder(new FileSink(out)));
    }

    void Base64Decode(const char *in, const char *out)
    {
        FileSource(in, true, new Base64Decoder(new FileSink(out)));
    }

    void HexEncode(const char *in, const char *out)
    {
        FileSource(in, true, new HexEncoder(new FileSink(out)));
    }

    void HexDecode(const char *in, const char *out)
    {
        FileSource(in, true, new HexDecoder(new FileSink(out)));
    }

};
NAMESPACE_END

#include <QString>
class CryptoPPUtil
{
public:
    static QString EncryptString(const QString& instr, const QString& passPhrase)
    {
        return QString::fromStdString(crypto.EncryptString(instr.toUtf8(), passPhrase.toUtf8()));
    }

    static QString DecryptString(const QString& instr, const QString& passPhrase)
    {
        return QString::fromStdString(crypto.DecryptString(instr.toUtf8(), passPhrase.toUtf8()));
    }

    static void EncryptFile(const QString& in, const QString& out, const QString& passPhrase)
    {
        crypto.EncryptFile(in.toUtf8(), out.toUtf8(), passPhrase.toUtf8());
    }

    static void DecryptFile(const QString& in, const QString& out, const QString& passPhrase)
    {
        crypto.DecryptFile(in.toUtf8(), out.toUtf8(), passPhrase.toUtf8());
    }

    static void GzipFile(const QString& in, const QString& out, int deflate_level)
    {
        crypto.GzipFile(in.toUtf8(), out.toUtf8(), deflate_level);
    }

    static void GunzipFile(const QString& in, const QString& out)
    {
        crypto.GunzipFile(in.toUtf8(), out.toUtf8());
    }

    static void Base64EncodeFile(const QString& in, const QString& out)
    {
        crypto.Base64Encode(in.toUtf8(), out.toUtf8());
    }

    static void Base64DecodeFile(const QString& in, const QString& out)
    {
        crypto.Base64Decode(in.toUtf8(), out.toUtf8());
    }

    static void HexEncodeFile(const QString& in, const QString& out)
    {
        crypto.HexEncode(in.toUtf8(), out.toUtf8());
    }

    static void HexDecodeFile(const QString& in, const QString& out)
    {
        crypto.HexDecode(in.toUtf8(), out.toUtf8());
    }

private:
    static inline CryptoPP::CryptoppAPI crypto;
};

#endif // CRYPTOPPUTIL_H
