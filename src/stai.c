#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <openssl/pem.h>

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

int main(){
    double time1, time2;
    // Initialiaze pairing
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

    // Init objects
    element_t P, s, P1, P2, g, si, rid, Rid, hid, sid, xid, Pid, kid, sign, signP;
    element_t t3, t4, t6, t7, t8;
    mpz_t t1, t2, t5;

    mpz_init(t1);
    mpz_init(t2);
    mpz_init(t5);
    element_init_G1(P, pairing);
    element_init_G1(P1, pairing);
    element_init_G1(P2, pairing);
    element_init_G1(Rid, pairing);
    element_init_G1(Pid, pairing);
    element_init_G1(sign, pairing);
    element_init_G1(signP, pairing);

    element_init_Zr(s, pairing);
    element_init_Zr(si, pairing);
    element_init_Zr(rid, pairing);
    element_init_Zr(hid, pairing);
    element_init_Zr(sid, pairing);
    element_init_Zr(t3, pairing);
    element_init_Zr(t4, pairing);
    element_init_Zr(t6, pairing);
    element_init_Zr(t7, pairing);
    element_init_Zr(xid, pairing);
    element_init_Zr(kid, pairing);

    element_init_GT(g, pairing);
    element_init_GT(t8, pairing);

    
    // Keygen
    //      Master keygen
    printf("KEYGEN...\n");
    element_random(P);
    element_random(s);
    element_mul_zn(P1, P, s);
    element_invert(si, s);
    element_mul_zn(P2, P, si);
    element_pairing(g, P, P);
    element_printf("Ppub : {P1 : %B, P2 : %B}\n", P1, P2);

    //      User keygen
    // Rid = rid * Ppub1
    element_mul_zn(Rid, P1, rid);
    // hid = H1(ID, Rid, Ppub1)
    // H1(m, a, b) = H(m)*mpz(a)*mpz(b)
    element_to_mpz(t1, Rid);
    element_to_mpz(t2, P1);
    element_from_hash(t3, "888888889", 9); // Identity
    element_printf("Element from hash : %B\n", t3);
    element_mul_mpz(t3, t3, t1);
    element_mul_mpz(hid, t3, t2);
    // sid = (rID + s-1*hid) mod q
    element_mul_zn(t4, si, hid);
    element_add(sid, rid, t4);

    //      Secret key user gen
    element_random(xid);
    //      Public key user gen
    element_mul_zn(Pid, P1, xid);
    time1 = pbc_get_time();
    // Signing
    // kid = H1(m, Rid, Pid)
    element_to_mpz(t5, Pid);
    element_from_hash(t6, "Sign this plz", 13);
    element_mul_mpz(t6, t6, t1);
    element_mul_mpz(kid, t6, t5);
    element_mul_zn(t7, kid, sid);
    element_add(t7, t7, xid);
    element_invert(t7, t7);
    element_mul_zn(sign, P2, t7);
    int n = pairing_length_in_bytes_x_only_G1(pairing);
    printf("Signature size : %d\n", n);
    element_printf("Signature of message :\n%B\n", sign);
    unsigned char *data = malloc(n);
    element_to_bytes_compressed(data, sign);
    char *enc = base64encode(data, n);
    printf("Signature : %s\n", enc);

    // Verify

    element_mul_zn(signP, P, hid);
    element_add(signP, signP, Rid);
    element_mul_zn(signP, signP, kid);
    element_add(signP, signP, Pid);
    element_pairing(t8, sign, signP);
    if (!element_cmp(t8, g)) {
        printf("Signature is valid!\n");
    } else {
        printf("Signature is invalid!\n");
    }
    time2 = pbc_get_time();
    printf("All time = %fs\n", time2 - time1);


    /*
    element_t P, s, P1, P2, g, si, rid, Rid, hid, sid, xid, Pid, kid, sign, signP;
    element_t t3, t4, t6, t7, t8;
    */
    element_clear(P);
    element_clear(s);
    element_clear(P1);
    element_clear(P2);
    element_clear(g);
    element_clear(si);
    element_clear(rid);
    element_clear(Rid);
    element_clear(hid);
    element_clear(sid);
    element_clear(xid);
    element_clear(Pid);
    element_clear(kid);
    element_clear(sign);
    element_clear(signP);
    element_clear(t3);
    element_clear(t4);
    element_clear(t6);
    element_clear(t7);
    element_clear(t8);
    pairing_clear(pairing);

    return 0;
}