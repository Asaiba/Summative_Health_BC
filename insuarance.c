// alu_chain.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>
#include <math.h>
#include <unistd.h>
#include <openssl/sha.h>   // <-- use OpenSSL's SHA256

#define MAX_TX_PER_BLOCK 128
#define MAX_PENDING_TX 256
#define MAX_CHAIN_BLOCKS 10000
#define MAX_PAYLOAD_LEN 4096
#define HASH_STR_LEN 65
#define ID_LEN 64
#define NOTES_LEN 256
#define FILENAME "alu_chain.txt"

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* ----------------------------- OpenSSL SHA-256 wrapper -----------------------------
    xUse OpenSSL's SHA256() instead of custom implementation.
------------------------------------------------------------------------------------*/

void sha256(const u8 *message, size_t len, u8 hash[32]) {
    // OpenSSL SHA256 produces 32-byte digest
    SHA256((const unsigned char *)message, len, hash);
}

void hash_to_hex(const u8 hash[32], char out[HASH_STR_LEN]) {
    for (int i = 0; i < 32; i++)
        sprintf(out + i*2, "%02x", hash[i]);
    out[64] = 0;
}

/* ----------------------------- Data structures --------------------------------------*/

typedef enum {ENROLLMENT, PREMIUM_PAYMENT, PREAUTH_REQUEST, CLAIM_SUBMISSION, CLAIM_DECISION} event_type_t;

const char *event_type_to_str(event_type_t e) {
    switch (e) {
        case ENROLLMENT: return "ENROLLMENT";
        case PREMIUM_PAYMENT: return "PREMIUM_PAYMENT";
        case PREAUTH_REQUEST: return "PREAUTH_REQUEST";
        case CLAIM_SUBMISSION: return "CLAIM_SUBMISSION";
        case CLAIM_DECISION: return "CLAIM_DECISION";
        default: return "UNKNOWN";
    }
}

typedef struct {
    char policy_id[ID_LEN];
    char member_id[ID_LEN];
    event_type_t event_type;
    char provider_id[ID_LEN];
    double amount;
    char diagnosis_code[32];
    char notes[NOTES_LEN];
    time_t timestamp;
} Transaction;

typedef struct {
    int block_id;
    time_t timestamp;
    int tx_count;
    Transaction txs[MAX_TX_PER_BLOCK];
    u8 prev_hash[32];
    u8 hash[32];
    uint64_t nonce;
} Block;

/* Chain & pending pool */
Block *chain[MAX_CHAIN_BLOCKS];
int chain_len = 0;

Transaction pending_txs[MAX_PENDING_TX];
int pending_count = 0;

/* PoW difficulty: number of leading hex '0' characters required in hash string. */
int difficulty = 3;

/* ----------------------------- Utilities -------------------------------------------*/

void print_hex(const u8 *data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

void mask_str(const char *in, char *out, int keep_prefix) {
    int n = (int)strlen(in);
    int keep = keep_prefix;
    for (int i = 0; i < n; i++) {
        if (i < keep) out[i] = in[i];
        else out[i] = '*';
    }
    out[n] = 0;
}

int is_valid_id(const char *s) {
    if (!s || strlen(s) == 0 || strlen(s) > 48) return 0;
    for (size_t i = 0; i < strlen(s); i++) {
        if (!(isalnum((unsigned char)s[i]) || s[i]=='-' || s[i]=='_')) return 0;
    }
    return 1;
}

/* ----------------------------- Serialization helpers ------------------------------*/

void tx_to_string(const Transaction *t, char *out, size_t out_len) {
    char tstamp[32];
    struct tm *tm = gmtime(&t->timestamp);
    strftime(tstamp, sizeof(tstamp), "%Y-%m-%dT%H:%M:%SZ", tm);

    snprintf(out, out_len,
            "{\"policy\":\"%s\",\"member\":\"%s\",\"event\":\"%s\",\"provider\":\"%s\",\"amount\":%.2f,\"diag\":\"%s\",\"notes\":\"%s\",\"ts\":\"%s\"}",
            t->policy_id, t->member_id, event_type_to_str(t->event_type), t->provider_id, t->amount, t->diagnosis_code, t->notes, tstamp);
}

void block_content_string(const Block *b, char *out, size_t out_len) {
    // Serialize block_id, timestamp, txs content, prev_hash, nonce
    char tmp[8192];
    size_t pos = 0;
    struct tm *tm = gmtime(&b->timestamp);
    char tstamp[32];
    strftime(tstamp, sizeof(tstamp), "%Y-%m-%dT%H:%M:%SZ", tm);

    pos += snprintf(out + pos, out_len - pos, "block:%d|ts:%s|nonce:%llu|prev:", b->block_id, tstamp, (unsigned long long)b->nonce);
    for (int i = 0; i < 32; i++) pos += snprintf(out + pos, out_len - pos, "%02x", b->prev_hash[i]);

    pos += snprintf(out + pos, out_len - pos, "|txs:[");
    for (int i = 0; i < b->tx_count; i++) {
        tx_to_string(&b->txs[i], tmp, sizeof(tmp));
        pos += snprintf(out + pos, out_len - pos, "%s", tmp);
        if (i < b->tx_count - 1) pos += snprintf(out + pos, out_len - pos, ",");
        if (pos >= out_len - 200) break;
    }
    snprintf(out + pos, out_len - pos, "]");
}

/* ----------------------------- Block & Tx management -------------------------------*/

Block *create_genesis_block() {
    Block *g = malloc(sizeof(Block));
    memset(g, 0, sizeof(Block));
    g->block_id = 0;
    g->timestamp = time(NULL);
    g->tx_count = 0;
    memset(g->prev_hash, 0, 32);
    g->nonce = 0;
    // compute hash
    char content[MAX_PAYLOAD_LEN];
    block_content_string(g, content, sizeof(content));
    sha256((u8*)content, strlen(content), g->hash);
    return g;
}

void add_tx_pending(const Transaction *t) {
    if (pending_count >= MAX_PENDING_TX) {
        printf("Pending pool full (max %d)\n", MAX_PENDING_TX);
        return;
    }
    pending_txs[pending_count++] = *t;
}

void print_tx_brief(const Transaction *t) {
    char mmasked[ID_LEN+1], pmasked[ID_LEN+1];
    mask_str(t->member_id, mmasked, 3);
    mask_str(t->policy_id, pmasked, 3);
    char tsbuf[32];
    struct tm *tm = gmtime(&t->timestamp);
    strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%dT%H:%M:%SZ", tm);
    printf("  %s | policy:%s member:%s provider:%s amount:%.2f diag:%s ts:%s\n",
        event_type_to_str(t->event_type), pmasked, mmasked, t->provider_id, t->amount, t->diagnosis_code, tsbuf);
}

/* ----------------------------- Mining / Proof-of-Work -------------------------------*/

int meets_difficulty(const char hexhash[HASH_STR_LEN], int difficulty) {
    for (int i = 0; i < difficulty; i++) {
        if (hexhash[i] != '0') return 0;
    }
    return 1;
}

void mine_block(Block *b) {
    char content[MAX_PAYLOAD_LEN];
    char hash_hex[HASH_STR_LEN];
    // simple incremental nonce search
    uint64_t nonce = 0;
    b->nonce = 0;
    while (1) {
        b->nonce = nonce;
        block_content_string(b, content, sizeof(content));
        sha256((u8*)content, strlen(content), b->hash);
        hash_to_hex(b->hash, hash_hex);
        if (meets_difficulty(hash_hex, difficulty)) {
            // mined
            break;
        }
        nonce++;
        if (nonce % 1000000 == 0) {
            // occasional progress print for long mines
            printf(".");
            fflush(stdout);
        }
    }
}

/* ----------------------------- Chain operations ------------------------------------*/

int add_block(Block *b) {
    if (chain_len >= MAX_CHAIN_BLOCKS) return 0;
    chain[chain_len++] = b;
    return 1;
}

void create_and_mine_block_from_pending() {
    if (pending_count == 0) {
        printf("No pending transactions to mine.\n");
        return;
    }
    Block *b = malloc(sizeof(Block));
    memset(b, 0, sizeof(Block));
    b->block_id = (chain_len==0) ? 0 : chain[chain_len-1]->block_id + 1;
    b->timestamp = time(NULL);
    b->tx_count = (pending_count > MAX_TX_PER_BLOCK) ? MAX_TX_PER_BLOCK : pending_count;
    for (int i = 0; i < b->tx_count; i++) b->txs[i] = pending_txs[i];
    // prev_hash
    if (chain_len == 0) memset(b->prev_hash, 0, 32);
    else memcpy(b->prev_hash, chain[chain_len-1]->hash, 32);

    printf("Mining block %d with %d tx(s) ...\n", b->block_id, b->tx_count);
    mine_block(b);
    char hash_hex[HASH_STR_LEN];
    hash_to_hex(b->hash, hash_hex);
    printf("\nMined block %d with nonce %llu hash=%s\n", b->block_id, (unsigned long long)b->nonce, hash_hex);

    // Append to chain
    add_block(b);

    // remove used pending txs
    if (pending_count > b->tx_count) {
        memmove(pending_txs, pending_txs + b->tx_count, sizeof(Transaction)*(pending_count - b->tx_count));
    }
    pending_count -= b->tx_count;
}

/* ----------------------------- Verify chain integrity ------------------------------*/

int verify_chain() {
    if (chain_len == 0) {
        printf("Chain empty.\n");
        return 0;
    }
    for (int i = 0; i < chain_len; i++) {
        Block *b = chain[i];
        // recompute hash and check pow
        char content[MAX_PAYLOAD_LEN];
        block_content_string(b, content, sizeof(content));
        u8 rehash[32];
        sha256((u8*)content, strlen(content), rehash);
        char rehex[HASH_STR_LEN];
        hash_to_hex(rehash, rehex);
        char stored_hex[HASH_STR_LEN];
        hash_to_hex(b->hash, stored_hex);

        if (strcmp(rehex, stored_hex) != 0) {
            printf("Block %d: hash mismatch! stored=%s recomputed=%s\n", b->block_id, stored_hex, rehex);
            return 0;
        }
        if (!meets_difficulty(stored_hex, difficulty)) {
            printf("Block %d: PoW requirement not met (difficulty=%d). Hash=%s\n", b->block_id, difficulty, stored_hex);
            return 0;
        }
        if (i > 0) {
            // check prev_hash link
            char prev_hex[HASH_STR_LEN];
            hash_to_hex(chain[i-1]->hash, prev_hex);
            char stored_prev_hex[HASH_STR_LEN];
            for (int k = 0; k < 32; k++) sprintf(stored_prev_hex + k*2, "%02x", b->prev_hash[k]);
            stored_prev_hex[64]=0;
            if (strcmp(prev_hex, stored_prev_hex) != 0) {
                printf("Block %d: prev_hash mismatch. expected=%s prev_in_block=%s\n", b->block_id, prev_hex, stored_prev_hex);
                return 0;
            }
        }
    }
    return 1;
}

/* ----------------------------- Save / Load persistent --------------------------------*/

void save_chain_to_file(const char *fname) {
    FILE *f = fopen(fname, "w");
    if (!f) { perror("fopen"); return; }
    // simple text format: blocks separated, all fields printable
    fprintf(f, "difficulty:%d\n", difficulty);
    for (int i = 0; i < chain_len; i++) {
        Block *b = chain[i];
        char hash_hex[HASH_STR_LEN];
        hash_to_hex(b->hash, hash_hex);
        fprintf(f, "BEGIN_BLOCK\n");
        fprintf(f, "block_id:%d\n", b->block_id);
        fprintf(f, "timestamp:%lld\n", (long long)b->timestamp);
        fprintf(f, "nonce:%llu\n", (unsigned long long)b->nonce);
        fprintf(f, "hash:%s\n", hash_hex);
        fprintf(f, "prev:");
        for (int j = 0; j < 32; j++) fprintf(f, "%02x", b->prev_hash[j]);
        fprintf(f, "\n");
        fprintf(f, "tx_count:%d\n", b->tx_count);
        for (int t = 0; t < b->tx_count; t++) {
            Transaction *tx = &b->txs[t];
            fprintf(f, "TX|%s|%s|%s|%s|%.2f|%s|%s|%lld\n",
                    tx->policy_id, tx->member_id, event_type_to_str(tx->event_type),
                    tx->provider_id, tx->amount, tx->diagnosis_code, tx->notes, (long long)tx->timestamp);
        }
        fprintf(f, "END_BLOCK\n");
    }
    fclose(f);
    printf("Chain saved to %s\n", fname);
}

void clear_chain_in_memory() {
    for (int i = 0; i < chain_len; i++) free(chain[i]);
    chain_len = 0;
}

int load_chain_from_file(const char *fname) {
    FILE *f = fopen(fname, "r");
    if (!f) { perror("fopen"); return 0; }
    clear_chain_in_memory();
    char line[1024];
    Block *curr = NULL;
    while (fgets(line, sizeof(line), f)) {
        // strip newline
        line[strcspn(line, "\r\n")] = 0;
        if (strncmp(line, "difficulty:", 11) == 0) {
            difficulty = atoi(line + 11);
        } else if (strcmp(line, "BEGIN_BLOCK") == 0) {
            curr = malloc(sizeof(Block));
            memset(curr, 0, sizeof(Block));
        } else if (strcmp(line, "END_BLOCK") == 0) {
            if (curr) add_block(curr);
            curr = NULL;
        } else if (curr != NULL) {
            if (strncmp(line, "block_id:",9)==0) curr->block_id = atoi(line+9);
            else if (strncmp(line, "timestamp:",10)==0) curr->timestamp = (time_t)atoll(line+10);
            else if (strncmp(line, "nonce:",6)==0) curr->nonce = (uint64_t)atoll(line+6);
            else if (strncmp(line, "hash:",5)==0) {
                char *h = line+5;
                for (int i = 0; i < 32; i++) {
                    unsigned int val;
                    sscanf(h + i*2, "%2x", &val);
                    curr->hash[i] = (u8)val;
                }
            } else if (strncmp(line, "prev:",5)==0) {
                char *h = line+5;
                for (int i = 0; i < 32; i++) {
                    unsigned int val;
                    sscanf(h + i*2, "%2x", &val);
                    curr->prev_hash[i] = (u8)val;
                }
            } else if (strncmp(line, "tx_count:",9)==0) curr->tx_count = atoi(line+9);
            else if (strncmp(line, "TX|",3)==0) {
                // TX|policy|member|EVENT|provider|amount|diag|notes|timestamp
                char *p = line + 3;
                Transaction tx;
                memset(&tx, 0, sizeof(tx));
                char evt[64];
                char notes_buf[NOTES_LEN];
                long long tstamp = 0;
                // crude parse using strtok
                // copy to temp
                char tmp[1024];
                strncpy(tmp, p, sizeof(tmp)-1); tmp[sizeof(tmp)-1]=0;
                char *parts[10];
                int idx=0;
                char *tok = strtok(tmp, "|");
                while (tok && idx < 10) { parts[idx++] = tok; tok = strtok(NULL, "|"); }
                if (idx >= 8) {
                    strncpy(tx.policy_id, parts[0], ID_LEN-1);
                    strncpy(tx.member_id, parts[1], ID_LEN-1);
                    strncpy(evt, parts[2], sizeof(evt)-1);
                    // map evt to enum
                    if (strcmp(evt, "ENROLLMENT")==0) tx.event_type = ENROLLMENT;
                    else if (strcmp(evt, "PREMIUM_PAYMENT")==0) tx.event_type = PREMIUM_PAYMENT;
                    else if (strcmp(evt, "PREAUTH_REQUEST")==0) tx.event_type = PREAUTH_REQUEST;
                    else if (strcmp(evt, "CLAIM_SUBMISSION")==0) tx.event_type = CLAIM_SUBMISSION;
                    else if (strcmp(evt, "CLAIM_DECISION")==0) tx.event_type = CLAIM_DECISION;
                    strncpy(tx.provider_id, parts[3], ID_LEN-1);
                    tx.amount = atof(parts[4]);
                    strncpy(tx.diagnosis_code, parts[5], sizeof(tx.diagnosis_code)-1);
                    strncpy(tx.notes, parts[6], NOTES_LEN-1);
                    tstamp = atoll(parts[7]);
                    tx.timestamp = (time_t)tstamp;
                    if (curr->tx_count < MAX_TX_PER_BLOCK) curr->txs[curr->tx_count++] = tx;
                }
            }
        }
    }
    fclose(f);
    printf("Loaded chain from %s with %d blocks (difficulty=%d)\n", fname, chain_len, difficulty);
    return 1;
}

/* ----------------------------- CLI / Main loop -------------------------------------*/

void show_help() {
    printf("Commands:\n");
    printf("  enroll            - create a policy/member enrollment\n");
    printf("  pay               - record premium payment\n");
    printf("  preauth           - log pre-authorization request/decision\n");
    printf("  claim_submit      - submit a claim\n");
    printf("  claim_decide      - add claim decision (approve/deny/partial)\n");
    printf("  mine              - mine a block including pending transactions\n");
    printf("  pending           - list pending transactions\n");
    printf("  view              - print full blockchain (brief)\n");
    printf("  viewblock <id>    - print block details\n");
    printf("  verify            - validate chain integrity and PoW\n");
    printf("  save              - save chain to disk (%s)\n", FILENAME);
    printf("  load              - load chain from disk (%s)\n", FILENAME);
    printf("  difficulty <n>    - set PoW difficulty (leading hex zeros)\n");
    printf("  help              - this help\n");
    printf("  exit              - quit\n");
}

void list_pending() {
    if (pending_count == 0) { printf("No pending transactions.\n"); return; }
    printf("Pending transactions (%d):\n", pending_count);
    for (int i = 0; i < pending_count; i++) {
        printf(" #%d: ", i);
        print_tx_brief(&pending_txs[i]);
    }
}

void print_chain_brief() {
    printf("Chain length: %d\n", chain_len);
    for (int i = 0; i < chain_len; i++) {
        Block *b = chain[i];
        char hex[HASH_STR_LEN]; hash_to_hex(b->hash, hex);
        printf("Block %d | txs:%d ts:%lld nonce:%llu hash:%s\n", b->block_id, b->tx_count, (long long)b->timestamp, (unsigned long long)b->nonce, hex);
    }
}

void print_block_detail(int id) {
    for (int i = 0; i < chain_len; i++) {
        Block *b = chain[i];
        if (b->block_id == id) {
            char hex[HASH_STR_LEN]; hash_to_hex(b->hash, hex);
            char prevhex[HASH_STR_LEN];
            for (int j = 0; j < 32; j++) sprintf(prevhex + j*2, "%02x", b->prev_hash[j]); prevhex[64]=0;
            printf("Block %d detail:\n", b->block_id);
            printf("  ts: %lld\n", (long long)b->timestamp);
            printf("  nonce: %llu\n", (unsigned long long)b->nonce);
            printf("  hash: %s\n", hex);
            printf("  prev: %s\n", prevhex);
            printf("  tx_count: %d\n", b->tx_count);
            for (int t = 0; t < b->tx_count; t++) {
                Transaction *tx = &b->txs[t];
                char tsbuf[32];
                struct tm *tm = gmtime(&tx->timestamp);
                strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%dT%H:%M:%SZ", tm);
                printf("   TX %d: event=%s policy=%s member=%s provider=%s amount=%.2f diag=%s notes=%s ts=%s\n",
                    t, event_type_to_str(tx->event_type), tx->policy_id, tx->member_id, tx->provider_id, tx->amount, tx->diagnosis_code, tx->notes, tsbuf);
            }
            return;
        }
    }
    printf("Block %d not found.\n", id);
}

void cli_loop() {
    char cmd[128];
    show_help();
    while (1) {
        printf("\nalu-chain> ");
        if (!fgets(cmd, sizeof(cmd), stdin)) break;
        // trim newline
        cmd[strcspn(cmd, "\r\n")] = 0;
        if (strlen(cmd) == 0) continue;

        // parse first token and args
        char *tok = strtok(cmd, " ");
        if (!tok) continue;

        if (strcmp(tok, "help") == 0) { show_help(); continue; }
        else if (strcmp(tok, "exit") == 0) { printf("Exiting.\n"); break; }
        else if (strcmp(tok, "pending") == 0) { list_pending(); continue; }
        else if (strcmp(tok, "view") == 0) { print_chain_brief(); continue; }
        else if (strcmp(tok, "verify") == 0) {
            printf("Verifying chain ...\n");
            if (verify_chain()) printf("Chain verification: OK\n"); else printf("Chain verification: FAILED\n");
            continue;
        } else if (strcmp(tok, "save") == 0) { save_chain_to_file(FILENAME); continue; }
        else if (strcmp(tok, "load") == 0) { load_chain_from_file(FILENAME); continue; }
        else if (strcmp(tok, "mine") == 0) { create_and_mine_block_from_pending(); continue; }
        else if (strcmp(tok, "difficulty") == 0) {
            char *a = strtok(NULL, " ");
            if (!a) { printf("Current difficulty=%d\n", difficulty); continue; }
            int d = atoi(a);
            if (d < 0 || d > 64) { printf("Invalid difficulty\n"); continue; }
            difficulty = d; printf("Difficulty set to %d\n", difficulty); continue;
        } else if (strcmp(tok, "viewblock") == 0) {
            char *arg = strtok(NULL, " ");
            if (!arg) { printf("Usage: viewblock <id>\n"); continue; }
            int id = atoi(arg);
            print_block_detail(id);
            continue;
        }

        /* Commands that produce new pending transactions: enroll, pay, preauth, claim_submit, claim_decide */
        Transaction tx;
        memset(&tx, 0, sizeof(tx));
        if (strcmp(tok, "enroll") == 0) {
            char policy[ID_LEN], member[ID_LEN], tier[32];
            printf("policy_id: "); if (!fgets(policy, sizeof(policy), stdin)) break; policy[strcspn(policy,"\r\n")]=0;
            printf("member_id: "); if (!fgets(member, sizeof(member), stdin)) break; member[strcspn(member,"\r\n")]=0;
            printf("coverage_tier (e.g., silver/gold): "); if (!fgets(tier, sizeof(tier), stdin)) break; tier[strcspn(tier,"\r\n")]=0;
            if (!is_valid_id(policy) || !is_valid_id(member)) { printf("Invalid IDs (alnum, -, _ allowed). Aborting.\n"); continue; }
            strncpy(tx.policy_id, policy, ID_LEN-1);
            strncpy(tx.member_id, member, ID_LEN-1);
            tx.event_type = ENROLLMENT;
            strncpy(tx.provider_id, "ALU_INSURANCE_OFFICE", ID_LEN-1);
            tx.amount = 0.0;
            strncpy(tx.diagnosis_code, "", sizeof(tx.diagnosis_code)-1);
            snprintf(tx.notes, sizeof(tx.notes), "coverage:%s", tier);
            tx.timestamp = time(NULL);
            add_tx_pending(&tx);
            printf("Enrollment transaction queued.\n");
            continue;
        } else if (strcmp(tok, "pay") == 0) {
            char policy[ID_LEN], member[ID_LEN], amount_buf[64];
            printf("policy_id: "); if (!fgets(policy, sizeof(policy), stdin)) break; policy[strcspn(policy,"\r\n")]=0;
            printf("member_id: "); if (!fgets(member, sizeof(member), stdin)) break; member[strcspn(member,"\r\n")]=0;
            printf("amount: "); if (!fgets(amount_buf, sizeof(amount_buf), stdin)) break; amount_buf[strcspn(amount_buf,"\r\n")]=0;
            double amt = atof(amount_buf);
            if (!is_valid_id(policy) || !is_valid_id(member) || amt <= 0.0) { printf("Invalid input. Aborting.\n"); continue; }
            strncpy(tx.policy_id, policy, ID_LEN-1); strncpy(tx.member_id, member, ID_LEN-1);
            tx.event_type = PREMIUM_PAYMENT;
            strncpy(tx.provider_id, "ALU_INSURANCE_OFFICE", ID_LEN-1);
            tx.amount = amt;
            strncpy(tx.diagnosis_code, "", sizeof(tx.diagnosis_code)-1);
            snprintf(tx.notes, sizeof(tx.notes), "premium payment");
            tx.timestamp = time(NULL);
            add_tx_pending(&tx);
            printf("Premium payment queued.\n");
            continue;
        } else if (strcmp(tok, "preauth") == 0) {
            char policy[ID_LEN], member[ID_LEN], prov[ID_LEN], reason[NOTES_LEN];
            printf("policy_id: "); if (!fgets(policy, sizeof(policy), stdin)) break; policy[strcspn(policy,"\r\n")]=0;
            printf("member_id: "); if (!fgets(member, sizeof(member), stdin)) break; member[strcspn(member,"\r\n")]=0;
            printf("provider_id: "); if (!fgets(prov, sizeof(prov), stdin)) break; prov[strcspn(prov,"\r\n")]=0;
            printf("notes (procedure, reason): "); if (!fgets(reason, sizeof(reason), stdin)) break; reason[strcspn(reason,"\r\n")]=0;
            if (!is_valid_id(policy) || !is_valid_id(member) || !is_valid_id(prov)) { printf("Invalid IDs. Aborting.\n"); continue; }
            strncpy(tx.policy_id, policy, ID_LEN-1); strncpy(tx.member_id, member, ID_LEN-1); strncpy(tx.provider_id, prov, ID_LEN-1);
            tx.event_type = PREAUTH_REQUEST;
            tx.amount = 0.0;
            strncpy(tx.diagnosis_code, "", sizeof(tx.diagnosis_code)-1);
            strncpy(tx.notes, reason, NOTES_LEN-1);
            tx.timestamp = time(NULL);
            add_tx_pending(&tx);
            printf("Preauth request queued.\n");
            continue;
        } else if (strcmp(tok, "claim_submit") == 0) {
            char policy[ID_LEN], member[ID_LEN], prov[ID_LEN], amtbuf[64], diag[32], notes[NOTES_LEN];
            printf("policy_id: "); if (!fgets(policy, sizeof(policy), stdin)) break; policy[strcspn(policy,"\r\n")]=0;
            printf("member_id: "); if (!fgets(member, sizeof(member), stdin)) break; member[strcspn(member,"\r\n")]=0;
            printf("provider_id: "); if (!fgets(prov, sizeof(prov), stdin)) break; prov[strcspn(prov,"\r\n")]=0;
            printf("amount: "); if (!fgets(amtbuf, sizeof(amtbuf), stdin)) break; amtbuf[strcspn(amtbuf,"\r\n")]=0;
            printf("diagnosis_code: "); if (!fgets(diag, sizeof(diag), stdin)) break; diag[strcspn(diag,"\r\n")]=0;
            printf("notes: "); if (!fgets(notes, sizeof(notes), stdin)) break; notes[strcspn(notes,"\r\n")]=0;
            double amt = atof(amtbuf);
            if (!is_valid_id(policy) || !is_valid_id(member) || !is_valid_id(prov) || amt <= 0.0) { printf("Invalid input. Aborting.\n"); continue; }
            strncpy(tx.policy_id, policy, ID_LEN-1); strncpy(tx.member_id, member, ID_LEN-1); strncpy(tx.provider_id, prov, ID_LEN-1);
            tx.event_type = CLAIM_SUBMISSION;
            tx.amount = amt;
            strncpy(tx.diagnosis_code, diag, sizeof(tx.diagnosis_code)-1);
            strncpy(tx.notes, notes, NOTES_LEN-1);
            tx.timestamp = time(NULL);
            add_tx_pending(&tx);
            printf("Claim submission queued.\n");
            continue;
        } else if (strcmp(tok, "claim_decide") == 0) {
            char policy[ID_LEN], member[ID_LEN], decision[32], amtbuf[64], notes[NOTES_LEN];
            printf("policy_id: "); if (!fgets(policy, sizeof(policy), stdin)) break; policy[strcspn(policy,"\r\n")]=0;
            printf("member_id: "); if (!fgets(member, sizeof(member), stdin)) break; member[strcspn(member,"\r\n")]=0;
            printf("decision (APPROVE/DENY/PARTIAL): "); if (!fgets(decision, sizeof(decision), stdin)) break; decision[strcspn(decision,"\r\n")]=0;
            printf("amount (paid by insurer, 0 if none): "); if (!fgets(amtbuf, sizeof(amtbuf), stdin)) break; amtbuf[strcspn(amtbuf,"\r\n")]=0;
            printf("notes: "); if (!fgets(notes, sizeof(notes), stdin)) break; notes[strcspn(notes,"\r\n")]=0;
            double amt = atof(amtbuf);
            if (!is_valid_id(policy) || !is_valid_id(member)) { printf("Invalid IDs. Aborting.\n"); continue; }
            strncpy(tx.policy_id, policy, ID_LEN-1); strncpy(tx.member_id, member, ID_LEN-1);
            tx.event_type = CLAIM_DECISION;
            strncpy(tx.provider_id, "ALU_INSURANCE_OFFICE", ID_LEN-1);
            tx.amount = amt;
            snprintf(tx.diagnosis_code, sizeof(tx.diagnosis_code), "%s", decision);
            strncpy(tx.notes, notes, NOTES_LEN-1);
            tx.timestamp = time(NULL);
            add_tx_pending(&tx);
            printf("Claim decision queued.\n");
            continue;
        } else {
            printf("Unknown command: %s\n", tok);
            show_help();
            continue;
        }
    } // end loop
}

/* ----------------------------- main -------------------------------------------------*/

int main(int argc, char **argv) {
    srand((unsigned int)time(NULL));
    // start with a genesis block
    Block *g = create_genesis_block();
    add_block(g);
    // optionally load existing chain
    if (access(FILENAME, F_OK) == 0) {
        printf("Found existing chain file '%s'. Load it? (y/N): ", FILENAME);
        char ans[8];
        if (fgets(ans, sizeof(ans), stdin)) {
            if (ans[0]=='y' || ans[0]=='Y') load_chain_from_file(FILENAME);
        }
    }
    cli_loop();
    // on exit, save
    printf("Save chain to %s before exit? (Y/n): ", FILENAME);
    char ans[8];
    if (fgets(ans, sizeof(ans), stdin)) {
        if (!(ans[0]=='n' || ans[0]=='N')) save_chain_to_file(FILENAME);
    }
    clear_chain_in_memory();
    return 0;
}
