#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
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

void register_id(char *id){
    // Setup pairing
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

    // Read public params and private key
    element_t s, P1, si;

    element_init_G1(P1, pairing);
    element_init_Zr(s, pairing);
    element_init_Zr(si, pairing);

    element_set0(P1);
    element_set0(s);
    read_element("p_params.txt", P1, "P1");
    read_element("s_key.txt", s, "s");
    element_invert(si, s);

    // Generate private key 
    element_t Rid, rid, t3, sid, hid, t4;
    mpz_t t1, t2;
    mpz_init(t1);
    mpz_init(t2);

    element_init_G1(Rid, pairing);
    element_init_Zr(rid, pairing);
    element_init_Zr(t4, pairing);
    element_init_Zr(hid, pairing);
    element_init_Zr(sid, pairing);
    element_init_Zr(t3, pairing);

    // Rid = rid * Ppub1
    element_random(rid);
    element_mul_zn(Rid, P1, rid);
    // hid = H1(ID, Rid, Ppub1)
    // H1(m, a, b) = H(m)*mpz(a)*mpz(b)
    element_to_mpz(t1, Rid);
    element_to_mpz(t2, P1);
    element_from_hash(t3, "888888889", 9); // Identity
    element_mul_mpz(t3, t3, t1);
    element_mul_mpz(hid, t3, t2);
    // sid = (rID + s-1*hid) mod q
    element_mul_zn(t4, si, hid);
    element_add(sid, rid, t4);

    write_element(stdout, sid, "sid");
    write_element(stdout, Rid, "Rid");

    element_clear(s);
    element_clear(P1);
    element_clear(si);
    element_clear(Rid);
    element_clear(rid);
    element_clear(t4);
    element_clear(hid);
    element_clear(sid);
    element_clear(t3);
    pairing_clear(pairing);
}

void setup(){
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

    element_t P, s, P1, P2, si, g;

    element_init_G1(P, pairing);
    element_init_G1(P1, pairing);
    element_init_G1(P2, pairing);    

    element_init_Zr(s, pairing);
    element_init_Zr(si, pairing);

    element_init_GT(g, pairing);


    // printf("Setup public params...\n");
    element_random(P);
    element_random(s);
    element_mul_zn(P1, P, s);
    element_invert(si, s);
    element_mul_zn(P2, P, si);
    element_pairing(g, P, P);

    // Write public params to p_params.txt (base64 encoded)

    FILE* fd = fopen("p_params.txt", "w");
    if(fd == NULL) {
        printf("Error opening output file\n");
        exit(1);
    } 
    write_element(fd, P, "P");
    write_element(fd, P1, "P1");
    write_element(fd, P2, "P2");
    write_element(fd, g, "g");
    fclose(fd);

    // Write secret key to s_key.txt (base64 encoded)

    fd = fopen("s_key.txt", "w");
    if(fd == NULL) {
        printf("Error opening output file\n");
        exit(1);
    } 
    write_element(fd, s, "s");
    fclose(fd);

    // Cleaning
    element_clear(P);
    element_clear(s);
    element_clear(P1);
    element_clear(P2);
    element_clear(g);
    element_clear(si);
    pairing_clear(pairing);
}

int main(int argc, char* argv[]){
    if(argc >= 2){
        if(!strcmp(argv[1], "setup")){
            // printf("Setup\n");
            setup();
            return 0;
        }
        else if(!strcmp(argv[1], "register") && argc >= 2){
            // printf("Registering %s\n", argv[2]);
            register_id(argv[2]);
            return 0;
        }
    }
    return 0;
}