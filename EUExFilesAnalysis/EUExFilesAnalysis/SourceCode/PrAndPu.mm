//
//  PrAndPu.m
//  EUExFilesAnalysis
//
//  Created by 郭杰 on 2019/4/15.
//  Copyright © 2019 songxingjie. All rights reserved.
//

#import "PrAndPu.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/objects.h"
#include "openssl/ossl_typ.h"
#include "openssl/pkcs12.h"

#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <string>



using std::cout;
using std::endl;
using std::stringstream;
using std::map;
using std::vector;
using std::string;


static NSMutableDictionary *aDic;

@interface PrAndPu()

@property(strong,nonatomic) NSMutableDictionary *dic;


@end

@implementation PrAndPu

//----------------------------------------------------------------------
string thumbprint(X509* x509)
{
    static const char hexbytes[] = "0123456789ABCDEF";
    unsigned int md_size;
    unsigned char md[EVP_MAX_MD_SIZE];
    const EVP_MD * digest = EVP_get_digestbyname("sha1");
    X509_digest(x509, digest, md, &md_size);
    stringstream ashex;
    for(int pos = 0; pos < md_size; pos++)
    {
        ashex << hexbytes[ (md[pos]&0xf0)>>4 ];
        ashex << hexbytes[ (md[pos]&0x0f)>>0 ];
    }
    return ashex.str();
}
//----------------------------------------------------------------------
int certversion(X509* x509)
{
    return X509_get_version(x509)+1;
}

string pem(X509* x509)
{
    BIO * bio_out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio_out, x509);
    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(bio_out, &bio_buf);
    string pem = string(bio_buf->data, bio_buf->length);
    BIO_free(bio_out);
    return pem;
}
//----------------------------------------------------------------------
void _asn1dateparse(const ASN1_TIME *time, int& year, int& month, int& day, int& hour, int& minute, int& second)
{
    const char* str = (const char*) time->data;
    size_t i = 0;
    if (time->type == V_ASN1_UTCTIME) {/* two digit year */
        year = (str[i++] - '0') * 10;
        year += (str[i++] - '0');
        year += (year < 70 ? 2000 : 1900);
    } else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
        year = (str[i++] - '0') * 1000;
        year+= (str[i++] - '0') * 100;
        year+= (str[i++] - '0') * 10;
        year+= (str[i++] - '0');
    }
    month  = (str[i++] - '0') * 10;
    month += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
    day  = (str[i++] - '0') * 10;
    day += (str[i++] - '0');
    hour = (str[i++] - '0') * 10;
    hour+= (str[i++] - '0');
    minute  = (str[i++] - '0') * 10;
    minute += (str[i++] - '0');
    second  = (str[i++] - '0') * 10;
    second += (str[i++] - '0');
}
//----------------------------------------------------------------------


//----------------------------------------------------------------------
string _asn1int(ASN1_INTEGER *bs)
{
    static const char hexbytes[] = "0123456789ABCDEF";
    stringstream ashex;
    for(int i=0; i<bs->length; i++)
    {
        ashex << hexbytes[ (bs->data[i]&0xf0)>>4  ] ;
        ashex << hexbytes[ (bs->data[i]&0x0f)>>0  ] ;
    }
    return ashex.str();
}
//----------------------------------------------------------------------
string _asn1string(ASN1_STRING *d)
{
    string asn1_string;
    if (ASN1_STRING_type(d) != V_ASN1_UTF8STRING) {
        unsigned char *utf8;
        int length = ASN1_STRING_to_UTF8( &utf8, d );
        asn1_string= string( (char*)utf8, length );
        OPENSSL_free( utf8 );
    } else {
        //        asn1_string = *ASN1_STRING_get0_data(d);
        asn1_string= string( (char*)ASN1_STRING_data(d), ASN1_STRING_length(d) );
    }
    return asn1_string;
}
//----------------------------------------------------------------------
string _subject_as_line(X509_NAME *subj_or_issuer)
{
    BIO * bio_out = BIO_new(BIO_s_mem());
    X509_NAME_print(bio_out,subj_or_issuer,0);
    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(bio_out, &bio_buf);
    string issuer = string(bio_buf->data, bio_buf->length);
    BIO_free(bio_out);
    return issuer;
}
//----------------------------------------------------------------------
std::map<string,string> _subject_as_map(X509_NAME *subj_or_issuer)
{
    std::map<string,string> m;
    for (int i = 0; i < X509_NAME_entry_count(subj_or_issuer); i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(subj_or_issuer, i);
        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        ASN1_OBJECT *o = X509_NAME_ENTRY_get_object(e);
        const char* key_name = OBJ_nid2sn( OBJ_obj2nid( o ) );
        m[key_name] = _asn1string(d);
    }
    return m;
}
//----------------------------------------------------------------------
string issuer_one_line(X509* x509)
{
    return _subject_as_line(X509_get_issuer_name(x509));
}
//----------------------------------------------------------------------
string subject_one_line(X509* x509)
{
    return _subject_as_line(X509_get_subject_name(x509));
}
//----------------------------------------------------------------------
std::map<string,string> subject(X509* x509)
{
    return _subject_as_map(X509_get_subject_name(x509));
}
//----------------------------------------------------------------------
std::map<string,string> issuer(X509* x509)
{
    return _subject_as_map(X509_get_issuer_name(x509));
}
//----------------------------------------------------------------------
string serial(X509* x509)
{
    return _asn1int(X509_get_serialNumber(x509));
}
//----------------------------------------------------------------------
string signature_algorithm(X509 *x509)
{
    
    int sig_nid = OBJ_obj2nid((x509)->sig_alg->algorithm);
    return string( OBJ_nid2ln(sig_nid) );
}
//----------------------------------------------------------------------
string public_key_type(X509 *x509)
{
    EVP_PKEY *pkey=X509_get_pubkey(x509);
    int key_type = EVP_PKEY_type(pkey->type);
    EVP_PKEY_free(pkey);
    if (key_type==EVP_PKEY_RSA) return "rsa";
    if (key_type==EVP_PKEY_DSA) return "dsa";
    if (key_type==EVP_PKEY_DH)  return "dh";
    if (key_type==EVP_PKEY_EC)  return "ecc";
    return "";
}
//----------------------------------------------------------------------
int public_key_size(X509 *x509)
{
    EVP_PKEY *pkey=X509_get_pubkey(x509);
    int key_type = EVP_PKEY_type(pkey->type);
    int keysize = -1; //or in bytes, RSA_size() DSA_size(), DH_size(), ECDSA_size();
    keysize = key_type==EVP_PKEY_RSA && pkey->pkey.rsa->n ? BN_num_bits(pkey->pkey.rsa->n) : keysize;
    keysize = key_type==EVP_PKEY_DSA && pkey->pkey.dsa->p ? BN_num_bits(pkey->pkey.dsa->p) : keysize;
    keysize = key_type==EVP_PKEY_DH  && pkey->pkey.dh->p  ? BN_num_bits(pkey->pkey.dh->p) : keysize;
    keysize = key_type==EVP_PKEY_EC  ? EC_GROUP_get_degree(EC_KEY_get0_group(pkey->pkey.ec)) : keysize;
    EVP_PKEY_free(pkey);
    return keysize;
}
//----------------------------------------------------------------------
string public_key_ec_curve_name(X509 *x509)
{
    EVP_PKEY *pkey=X509_get_pubkey(x509);
    int key_type = EVP_PKEY_type(pkey->type);
    if (key_type==EVP_PKEY_EC)
    {
        const EC_GROUP *group = EC_KEY_get0_group(pkey->pkey.ec);
        int name = (group != NULL) ? EC_GROUP_get_curve_name(group) : 0;
        return name ? OBJ_nid2sn(name) : "";
    }
    return "";
}
//----------------------------------------------------------------------
string asn1datetime_isodatetime(const ASN1_TIME *tm)
{
    int year=0, month=0, day=0, hour=0, min=0, sec=0;
    _asn1dateparse(tm,year,month,day,hour,min,sec);
    
    char buf[25]="";
    snprintf(buf, sizeof(buf)-1, "%04d-%02d-%02d %02d:%02d:%02d GMT", year, month, day, hour, min, sec);
    return string(buf);
}
//----------------------------------------------------------------------
string asn1date_isodate(const ASN1_TIME *tm)
{
    int year=0, month=0, day=0, hour=0, min=0, sec=0;
    _asn1dateparse(tm,year,month,day,hour,min,sec);
    
    char buf[25]="";
    snprintf(buf, sizeof(buf)-1, "%04d-%02d-%02d", year, month, day);
    return string(buf);
}
//----------------------------------------------------------------------

vector<string> subject_alt_names(X509 *x509)
{
    vector<string> list;
    GENERAL_NAMES* subjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    for (int i = 0; i < sk_GENERAL_NAME_num(subjectAltNames); i++)
    {
        GENERAL_NAME* gen = sk_GENERAL_NAME_value(subjectAltNames, i);
        if (gen->type == GEN_URI || gen->type == GEN_DNS || gen->type == GEN_EMAIL)
        {
            ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
            string san = string( (char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str) );
            list.push_back( san );
        }
        else if (gen->type == GEN_IPADD)
        {
            unsigned char *p = gen->d.ip->data;
            if(gen->d.ip->length == 4)
            {
                stringstream ip;
                ip << (int)p[0] << '.' << (int)p[1] << '.' << (int)p[2] << '.' << (int)p[3];
                list.push_back( ip.str() );
            }
            else //if(gen->d.ip->length == 16) //ipv6?
            {
                //std::cerr << "Not implemented: parse sans ("<< __FILE__ << ":" << __LINE__ << ")" << endl;
            }
        }
        else
        {
            //std::cerr << "Not implemented: parse sans ("<< __FILE__ << ":" << __LINE__ << ")" << endl;
        }
    }
    GENERAL_NAMES_free(subjectAltNames);
    return list;
}

//----------------------------------------------------------------------
vector<string> ocsp_urls(X509 *x509)
{
    vector<string> list;
    STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(x509);
    for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list); j++)
    {
        list.push_back( string( sk_OPENSSL_STRING_value(ocsp_list, j) ) );
    }
    X509_email_free(ocsp_list);
    return list;
}
//----------------------------------------------------------------------

vector<string> crl_urls(X509 *x509)
{
    vector<string> list;
    int nid = NID_crl_distribution_points;
    STACK_OF(DIST_POINT) * dist_points =(STACK_OF(DIST_POINT) *)X509_get_ext_d2i(x509, nid, NULL, NULL);
    for (int j = 0; j < sk_DIST_POINT_num(dist_points); j++)
    {
        DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
        DIST_POINT_NAME    *distpoint = dp->distpoint;
        if (distpoint->type==0)//fullname GENERALIZEDNAME
        {
            for (int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++)
            {
                GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
                ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
                list.push_back( string( (char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str) ) );
            }
        }
        else if (distpoint->type==1)//relativename X509NAME
        {
            STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
            for (int k = 0; k < sk_X509_NAME_ENTRY_num(sk_relname); k++)
            {
                X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, k);
                ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
                list.push_back( string( (char*)ASN1_STRING_data(d), ASN1_STRING_length(d) ) );
            }
        }
    }
    CRL_DIST_POINTS_free(dist_points);
    return list;
}

//----------------------------------------------------------------------
void parseCert1(X509* x509)
{
    cout <<"--------------------" << endl;
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    //PEM_write_bio_X509(bio_out, x509);//STD OUT the PEM
    X509_print(bio_out, x509);//STD OUT the details
    //X509_print_ex(bio_out, x509, XN_FLAG_COMPAT, X509_FLAG_COMPAT);//STD OUT the details
    BIO_free(bio_out);
}
//----------------------------------------------------------------------

void parseCert2(X509* x509)
{
    cout <<"--------------------" << endl;
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    
    long l = X509_get_version(x509);
    BIO_printf(bio_out, "Version: %ld\n", l+1);
    
    ASN1_INTEGER *bs = X509_get_serialNumber(x509);
    BIO_printf(bio_out,"Serial: ");
    for(int i=0; i<bs->length; i++) {
        BIO_printf(bio_out,"%02x",bs->data[i] );
    }
    BIO_printf(bio_out,"\n");
    
    X509_signature_print(bio_out, x509->sig_alg, NULL);
    
    BIO_printf(bio_out,"Issuer: ");
    X509_NAME_print(bio_out,X509_get_issuer_name(x509),0);
    BIO_printf(bio_out,"\n");
    
    BIO_printf(bio_out,"Valid From: ");
    ASN1_TIME_print(bio_out,X509_get_notBefore(x509));
    BIO_printf(bio_out,"\n");
    
    BIO_printf(bio_out,"Valid Until: ");
    ASN1_TIME_print(bio_out,X509_get_notAfter(x509));
    BIO_printf(bio_out,"\n");
    
    BIO_printf(bio_out,"Subject: ");
    X509_NAME_print(bio_out,X509_get_subject_name(x509),0);
    BIO_printf(bio_out,"\n");
    
    EVP_PKEY *pkey=X509_get_pubkey(x509);
    EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
    EVP_PKEY_free(pkey);
    
    X509_CINF *ci=x509->cert_info;
    X509V3_extensions_print(bio_out, (char*)"X509v3 extensions", ci->extensions, X509_FLAG_COMPAT, 0);
    
    X509_signature_print(bio_out, x509->sig_alg, x509->signature);
    BIO_free(bio_out);
}

//----------------------------------------------------------------------
void parseCert3(X509* x509){
    
    aDic = [[NSMutableDictionary alloc] init];
    
    cout <<"--------------------" << endl;
    //cout << pem(x509) << endl;
    cout <<"Thumbprint: " << thumbprint(x509) << endl;
    
//    string str = thumbprint(x509);
//    aStr = [NSString stringWithUTF8String:str.c_str()];
//    NSLog(@"aStr == %@",aStr);
    
  
    cout <<"Version: " << certversion(x509) << endl;
    NSString *versionStr = [NSString stringWithFormat:@"%d",certversion(x509)];
    NSLog(@"versionStr ======= %@",versionStr);
    
    
    cout <<"Serial: " << serial(x509) << endl;
    cout <<"Issuer: " << issuer_one_line(x509) << endl;
    
    map<string,string> ifields = issuer(x509);
    NSString *issuerString = @"";
    for(map<string, string>::iterator i = ifields.begin(), ix = ifields.end(); i != ix; i++ ){
         cout << " * " << i->first << " : " << i->second << endl;
        string str1 = i->first;
        string str2 = i->second;
        NSString * aString1 = [NSString stringWithUTF8String:str1.c_str()];
        NSString * aString2 = [NSString stringWithUTF8String:str2.c_str()];
        NSString *issuerStringTemp = [NSString stringWithFormat:@"%@= %@",aString1,aString2];
        issuerString = [NSString stringWithFormat:@"%@,%@", issuerString, issuerStringTemp];
    }
    NSLog(@"issuerString===%@",issuerString);
    [aDic setValue:issuerString forKey:@"issuerDNName"];
    
    
    cout <<"Subject: "    << subject_one_line(x509) << endl;
    
    map<string,string> sfields = subject(x509);
    NSString *subString = @"";
    for(map<string, string>::iterator i = sfields.begin(), ix = sfields.end(); i != ix; i++ )
    {
         cout << " * " <<  i->first << " : " << i->second << endl;
        string str1 = i->first;
        string str2 = i->second;
        NSString * aString1 = [NSString stringWithUTF8String:str1.c_str()];
        NSString * aString2 = [NSString stringWithUTF8String:str2.c_str()];
        NSString *subStringTemp = [NSString stringWithFormat:@"%@=%@",aString1,aString2];
        subString = [NSString stringWithFormat:@"%@,%@", subString, subStringTemp];
    }
    NSLog(@"%@",subString);
    [aDic setValue:subString forKey:@"subjectDN"];
    
   
    cout <<"SignatureAlgorithm: "    << signature_algorithm(x509) << endl;
    cout <<"PublicKeyType: "    << public_key_type(x509) << public_key_ec_curve_name(x509) << endl;
    cout <<"PublicKeySize: "    << public_key_size(x509) << endl;
    cout <<"NotBefore: "    << asn1datetime_isodatetime(X509_get_notBefore(x509)) << endl;
    cout <<"NotAfter: "    << asn1datetime_isodatetime(X509_get_notAfter(x509)) << endl;
    cout <<"SubjectAltName(s):" << endl;
    
    
    vector<string> sans = subject_alt_names(x509);
    for(int i=0, ix=sans.size(); i<ix; i++) {
        cout << " " << sans[i] << endl;
    }
    cout <<"CRL URLs:" << endl;
    
    vector<string> crls = crl_urls(x509);
    for(int i=0, ix=crls.size(); i<ix; i++) {
        cout << " " << crls[i] << endl;
    }
    cout <<"OCSP URLs:" << endl;
    
    vector<string> urls = ocsp_urls(x509);
    for(int i=0, ix=urls.size(); i<ix; i++) {
        cout << " " << urls[i] << endl;
    }
    
    
    [aDic setValue:[NSString stringWithUTF8String:thumbprint(x509).c_str()] forKey:@"Thumbprint"];
    [aDic setValue:versionStr forKey:@"version:"];
    [aDic setValue:[NSString stringWithUTF8String:serial(x509).c_str()] forKey:@"serialNumberLong"];
    [aDic setValue:[NSString stringWithUTF8String:signature_algorithm(x509).c_str()] forKey:@"sigAlgName"];
   // [aDic setValue:[NSString stringWithUTF8String:public_key_ec_curve_name(x509).c_str()] forKey:@"PublicKeyCurveName"];
    [aDic setValue:[NSString stringWithUTF8String:public_key_type(x509).c_str()] forKey:@"PublicKeyType:"];
    
    [aDic setValue:[NSString stringWithUTF8String:asn1datetime_isodatetime(X509_get_notBefore(x509)).c_str()] forKey:@"notBefore"];
    [aDic setValue:[NSString stringWithUTF8String:asn1datetime_isodatetime(X509_get_notAfter(x509)).c_str()] forKey:@"NotAfter"];
    NSLog(@"aDic =========== %@",aDic);
    
}

- (void)analyticalCertificateFromPKCS12File:(NSString *)pkcsPath passphrase:(NSString *)pkcsPassword{
    
    PKCS12 *p12 = NULL;
    X509 *x509 = NULL;
    EVP_PKEY *pKey = NULL;
    STACK_OF(X509) *ca = NULL;
    
    const char *pass = [pkcsPassword UTF8String];
  
    SSLeay_add_all_algorithms();
    ERR_load_CRYPTO_strings();
    
    BIO *bio_mem = BIO_new_file([pkcsPath UTF8String], "r");
    p12 = d2i_PKCS12_bio(bio_mem, NULL);
    BIO_free(bio_mem);
    PKCS12_parse(p12, (const char*)pass, &pKey, &x509, &ca);
    
    //    NSLog(@"%@",x509);
    
    parseCert1(x509);
    parseCert2(x509);
    parseCert3(x509);
    //    BIO_free(bio_mem);
    X509_free(x509);
    [aDic setValue:@"ok" forKey:@"status"];
    _dicInfo = aDic;
    NSLog(@"_dicInfo_dicInfo_dicInfo_dicInfo ==== %@",_dicInfo);
}

- (NSMutableDictionary *)dicInfo{
    if (!_dicInfo) {
        _dicInfo = [[NSMutableDictionary alloc] init];
    }
    return _dicInfo;
    
}



@end
