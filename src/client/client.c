#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <string.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *base64encode (const void *b64_encode_this, int encode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    BUF_MEM *mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
    BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
    BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); //Records base64 encoded data.
    BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
    BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.
    return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    char *base64_decoded = calloc( (decode_this_many_bytes*3)/4+1, sizeof(char) ); //+1 = null.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
    BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
    BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
    int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
    while ( 0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ //Read byte-by-byte.
        decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
    } //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    return base64_decoded;        //Returns base-64 decoded data with trailing null terminator.
}

void write_element(FILE* f, element_t e, char* name){
    int n = element_length_in_bytes(e);
    unsigned char *data = malloc(n);
    element_to_bytes(data, e);
    char* enc = base64encode(data, n);
    fprintf(f, "%s:%s\n", name, enc);
    free(data);
}

void read_element(char *filename, element_t e, char *target_name){
    FILE* fp = fopen(filename, "r");
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    if (fp == NULL){
        printf("Failure opening input file %s\n", filename);
        exit(1);
    }
    char name[3], value[250];
    while((read = getline(&line, &len, fp)) != -1 && strcmp(name, target_name)){
        sscanf(line, "%[^:]:%s", name, value);
    }
    int n = element_length_in_bytes(e);
    int bytes_to_decode = strlen(value);
    char *base64_decoded = base64decode(value, bytes_to_decode);
    element_from_bytes(e, base64_decoded);
    fclose(fp);
    if (line)
        free(line);
}

void read_from_base64(char* b64, element_t e){
    int bytes_to_decode = strlen(b64);
    char *base64_decoded = base64decode(b64, bytes_to_decode);
    element_from_bytes(e, base64_decoded);
    free(base64_decoded);
}

void sign(unsigned char *message){
    // Setup pairing
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

    element_t kid, sid, xid, P2, Pid, Rid, t3, sign;
    mpz_t t1, t2;

    mpz_init(t1);
    mpz_init(t2);
    element_init_G1(P2, pairing);
    element_init_G1(Pid, pairing);
    element_init_G1(Rid, pairing);
    element_init_G1(sign, pairing);

    element_init_Zr(kid, pairing);
    element_init_Zr(sid, pairing);
    element_init_Zr(xid, pairing);
    element_init_Zr(t3, pairing);

    read_element("params.txt", P2, "P2");
    read_element("private.key", xid, "xid"),
    read_element("private.key", sid, "sid"),
    read_element("public.key", Pid, "Pid"),
    read_element("public.key", Rid, "Rid"),

    element_to_mpz(t1, Pid);
    element_to_mpz(t2, Rid);

    // kid = H1(m, Rid, Pid)
    element_from_hash(kid, message, 32); // 32 because input is SHA256
    element_mul_mpz(kid, kid, t1);
    element_mul_mpz(kid, kid, t2);

    // sign = (kid*sid+xid)-1 * P2

    element_mul_zn(t3, kid, sid);
    element_add(t3, t3, xid);
    element_invert(t3, t3);

    element_mul_zn(sign, P2, t3);

    // Base64-encode and send sign
    int n = pairing_length_in_bytes_G1(pairing);
    unsigned char* data = malloc(n);
    element_to_bytes(data, sign);
    char *enc = base64encode(data, n);

    printf("%s\n", enc);
    free(data);
    free(enc);
    pairing_clear(pairing);
}

int verify(unsigned char *message, char *signature, unsigned char* id_h, char* Rid_b64, char* Pid_b64){
    // Setup pairing
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");


    element_t hid, Rid, Pid, kid, m, sign, signP, g, id, t1, P1, P;
    mpz_t P1_mpz, Rid_mpz, Pid_mpz;

    mpz_init(P1_mpz);
    mpz_init(Rid_mpz);
    mpz_init(Pid_mpz);
    element_init_G1(sign, pairing);
    element_init_G1(signP, pairing);
    element_init_G1(Rid, pairing);
    element_init_G1(Pid, pairing);
    element_init_G1(P1, pairing);
    element_init_G1(P, pairing);

    element_init_Zr(kid, pairing);
    element_init_Zr(id, pairing);
    element_init_Zr(hid, pairing);
    element_init_Zr(m, pairing);

    element_init_GT(t1, pairing);
    element_init_GT(g, pairing);


    // Load from file

    read_element("params.txt", g, "g");
    read_element("params.txt", P1, "P1");
    read_element("params.txt", P, "P1");

    // Load from input 
    read_from_base64(signature, sign);
    read_from_base64(Pid_b64, Pid);
    read_from_base64(Rid_b64, Rid);

    element_from_hash(id, id_h, 32);
    element_from_hash(m, message, 32);

    // Compute hid = H1(ID, Rid, P1)
    // element_set1(hid);
    element_to_mpz(Rid_mpz, Rid);
    element_to_mpz(P1_mpz, P1);
    element_mul_mpz(hid, id, Rid_mpz);
    element_mul_mpz(hid, hid, P1_mpz);

    // Compute kid = H1(m, Rid, Pid)
    // element_set1(kid);
    element_to_mpz(Pid_mpz, Pid);
    element_mul_mpz(kid, m, Rid_mpz);
    element_mul_mpz(kid, kid, Pid_mpz);

    // Compute signP = kid(Rid+hid*P)+Pid
    element_set1(signP);
    element_mul_zn(signP, P, hid);
    element_add(signP, signP, Rid);
    element_mul_zn(signP, signP, kid);
    element_add(signP, signP, Pid);
    element_pairing(t1, sign, signP);

    // Verify
    if (!element_cmp(t1, g)) {
        printf("Signature is valid!\n");
    } else {
        printf("Signature is invalid!\n");
    }

    pairing_clear(pairing);
}

void setup(){
    // Setup pairing
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

    element_t xid, Pid, P1;

    element_init_G1(Pid, pairing);
    element_init_G1(P1, pairing);
    element_init_Zr(xid, pairing);

    read_element("params.txt", P1, "P1");

    element_random(xid);
    element_mul_zn(Pid, P1, xid);
    write_element(stdout, Pid, "Pid");
    write_element(stdout, xid, "xid");

    pairing_clear(pairing);
}



int main(int argc, char* argv[]){
    if(argc >= 2){
        if(argc == 3 && !strcmp(argv[1], "sign")){
            sign(argv[2]);
        }
        if(!strcmp(argv[1], "setup")){
            setup();
        }
        if(argc == 7 && !strcmp(argv[1], "verify")){
            verify(argv[2], argv[3], argv[4], argv[5], argv[6]);
        }
    }
    return 0;
}