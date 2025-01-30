#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>

// Shared variables for thread counting
static int total_addresses = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int should_continue = 1;

// Base58 character set
static const char *BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Thread data structure
typedef struct {
    int thread_id;
    int addresses_generated;
} ThreadData;

// Shared memory structure
typedef struct {
    long total_addresses;
    pthread_mutex_t mutex;
} SharedMemory;

// Global pointer to shared memory
static SharedMemory* shared_mem = NULL;

void base58_encode(unsigned char *input, size_t input_len, char *output) {
    BIGNUM *bn = BN_new();
    BIGNUM *bn58 = BN_new();
    BIGNUM *bn0 = BN_new();
    BIGNUM *dv = BN_new();
    BIGNUM *rem = BN_new();
    
    BN_bin2bn(input, input_len, bn);
    BN_set_word(bn58, 58);
    BN_zero(bn0);
    
    char temp[100];
    int temp_pos = 0;
    
    while (BN_cmp(bn, bn0) > 0) {
        BN_div(dv, rem, bn, bn58, BN_CTX_new());
        BN_copy(bn, dv);
        temp[temp_pos++] = BASE58_CHARS[BN_get_word(rem)];
    }
    
    for (size_t i = 0; i < input_len && input[i] == 0; i++) {
        temp[temp_pos++] = BASE58_CHARS[0];
    }
    
    for (int i = temp_pos - 1; i >= 0; i--) {
        *output++ = temp[i];
    }
    *output = '\0';
    
    BN_free(bn);
    BN_free(bn58);
    BN_free(bn0);
    BN_free(dv);
    BN_free(rem);
}

void generate_single_address(EVP_PKEY_CTX *ctx, EVP_MD_CTX *md_ctx, char *address) {
    EVP_PKEY *key = NULL;
    unsigned char *pub_key_bytes = NULL;
    size_t pub_key_size;
    
    EVP_PKEY_keygen(ctx, &key);
    
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_key_size);
    pub_key_bytes = OPENSSL_malloc(pub_key_size);
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub_key_bytes, pub_key_size, NULL);

    unsigned char sha256_result[EVP_MAX_MD_SIZE];
    unsigned char ripemd160_result[EVP_MAX_MD_SIZE];
    unsigned int sha256_len, ripemd160_len;

    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, pub_key_bytes, pub_key_size);
    EVP_DigestFinal_ex(md_ctx, sha256_result, &sha256_len);

    EVP_DigestInit_ex(md_ctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(md_ctx, sha256_result, sha256_len);
    EVP_DigestFinal_ex(md_ctx, ripemd160_result, &ripemd160_len);

    unsigned char version_ripemd160_result[21];
    version_ripemd160_result[0] = 0x00;
    memcpy(version_ripemd160_result + 1, ripemd160_result, ripemd160_len);

    unsigned char checksum[EVP_MAX_MD_SIZE];
    
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, version_ripemd160_result, 21);
    EVP_DigestFinal_ex(md_ctx, sha256_result, &sha256_len);
    
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, sha256_result, sha256_len);
    EVP_DigestFinal_ex(md_ctx, checksum, &sha256_len);

    unsigned char binary_address[25];
    memcpy(binary_address, version_ripemd160_result, 21);
    memcpy(binary_address + 21, checksum, 4);

    base58_encode(binary_address, 25, address);

    EVP_PKEY_free(key);
    OPENSSL_free(pub_key_bytes);
}

// Function to setup shared memory
SharedMemory* create_shared_memory() {
    // First try to unlink any existing shared memory
    shm_unlink("/bitcoin_benchmark");
    
    int fd = shm_open("/bitcoin_benchmark", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("shm_open failed");
        return NULL;
    }

    // Set the size of the shared memory segment
    size_t size = sizeof(SharedMemory);
    if (ftruncate(fd, size) == -1) {
        perror("ftruncate failed");
        close(fd);
        shm_unlink("/bitcoin_benchmark");
        return NULL;
    }

    // Map the shared memory segment
    SharedMemory* mem = (SharedMemory*)mmap(NULL, size, 
                                          PROT_READ | PROT_WRITE, 
                                          MAP_SHARED, fd, 0);
    
    if (mem == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        shm_unlink("/bitcoin_benchmark");
        return NULL;
    }

    // Initialize the mutex with proper attributes
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) {
        perror("pthread_mutexattr_setpshared failed");
        munmap(mem, size);
        close(fd);
        shm_unlink("/bitcoin_benchmark");
        return NULL;
    }

    if (pthread_mutex_init(&mem->mutex, &attr) != 0) {
        perror("pthread_mutex_init failed");
        pthread_mutexattr_destroy(&attr);
        munmap(mem, size);
        close(fd);
        shm_unlink("/bitcoin_benchmark");
        return NULL;
    }

    pthread_mutexattr_destroy(&attr);
    
    // Initialize counter
    mem->total_addresses = 0;
    
    // Close the file descriptor (the mapping remains valid)
    close(fd);
    
    return mem;
}

// Modify thread_function to update shared memory
void* thread_function(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    char address[50];
    
    // Initialize OpenSSL context for this thread
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0) {
        return NULL;
    }
    
    md_ctx = EVP_MD_CTX_new();
    
    while (should_continue) {
        generate_single_address(ctx, md_ctx, address);
        data->addresses_generated++;
        
        pthread_mutex_lock(&mutex);
        total_addresses++;
        pthread_mutex_unlock(&mutex);

        // Update shared memory counter
        pthread_mutex_lock(&shared_mem->mutex);
        shared_mem->total_addresses++;
        pthread_mutex_unlock(&shared_mem->mutex);
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_MD_CTX_free(md_ctx);
    return NULL;
}

void run_benchmark(int num_threads, int duration, int process_id) {
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    ThreadData* thread_data = malloc(num_threads * sizeof(ThreadData));
    
    printf("Process %d - Starting benchmark with %d threads for %d seconds...\n", 
           process_id, num_threads, duration);
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].addresses_generated = 0;
        pthread_create(&threads[i], NULL, thread_function, &thread_data[i]);
    }
    
    // Monitor progress
    time_t start_time = time(NULL);
    time_t end_time = start_time + duration;
    
    while (time(NULL) < end_time) {
        sleep(1);
        printf("Generated %d addresses...\r", total_addresses);
        fflush(stdout);
    }
    
    // Signal threads to stop and wait for them
    should_continue = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Calculate results
    double total_time = difftime(time(NULL), start_time);
    double rate = total_addresses / total_time;
    
    printf("\nProcess %d Results:\n", process_id);
    printf("Process addresses generated: %d\n", total_addresses);
    printf("Time elapsed: %.2f seconds\n", total_time);
    printf("Process generation rate: %.2f addresses per second\n", rate);
    
    // Per-thread statistics
    for (int i = 0; i < num_threads; i++) {
        printf("Process %d Thread %d generated %d addresses\n", 
               process_id, thread_data[i].thread_id, 
               thread_data[i].addresses_generated);
    }
    
    free(threads);
    free(thread_data);
}

void print_collision_probability(double total_addresses, long addresses_per_second) {
    // Known addresses statistics
    const double known_addresses = 10e9;  // 10 billion
    const double daily_new_addresses = 1000.0;
    const double days_in_year = 365.25;
    
    printf("\n=== Collision Analysis ===\n");
    printf("Current Bitcoin network statistics:\n");
    printf("- Known addresses: %.2e (10 billion)\n", known_addresses);
    printf("- New addresses per day: %.2f\n", daily_new_addresses);
    printf("- New addresses per year: %.2e\n", daily_new_addresses * days_in_year);
    
    // Calculate probabilities
    double prob_single_collision = known_addresses / total_addresses;
    double prob_yearly_collision = (known_addresses + (daily_new_addresses * days_in_year)) / total_addresses;
    
    printf("\nProbability Analysis:\n");
    printf("- Probability of generating an existing address (current): %.2e\n", prob_single_collision);
    printf("- Probability of generating an existing address (after 1 year): %.2e\n", prob_yearly_collision);
    
    // Calculate attempts needed for different probability thresholds
    double attempts_50_percent = 0.5 * total_addresses / known_addresses;
    double attempts_99_percent = 0.99 * total_addresses / known_addresses;
    
    printf("\nAttempts needed for collision:\n");
    printf("- For 50%% chance: %.2e attempts\n", attempts_50_percent);
    printf("- For 99%% chance: %.2e attempts\n", attempts_99_percent);
    
    // Time needed with current generation speed
    double time_50_percent = attempts_50_percent / addresses_per_second;
    double time_99_percent = attempts_99_percent / addresses_per_second;
    
    printf("\nTime needed with your generation speed (%.2e addr/s):\n", (double)addresses_per_second);
    printf("- For 50%% chance: %.2e years\n", time_50_percent / (365.25 * 24 * 3600));
    printf("- For 99%% chance: %.2e years\n", time_99_percent / (365.25 * 24 * 3600));
    
    // Birthday attack probability
    double birthday_prob = 1.0 - exp(-pow(known_addresses, 2) / (2 * total_addresses));
    printf("\nBirthday Attack Analysis:\n");
    printf("- Probability of any collision in known addresses: %.2e\n", birthday_prob);
    
    // Interesting comparisons
    printf("\nFor perspective:\n");
    printf("- You are %.2e times more likely to win the lottery jackpot\n", 
           1 / (292201338.0 * prob_single_collision));  // Using Powerball odds
    printf("- You are %.2e times more likely to be struck by lightning\n",
           1 / (500000.0 * prob_single_collision));  // Lifetime odds of being struck by lightning
}

double print_time_analysis(long addresses_per_second) {
    // Use double to handle large numbers
    double total_addresses = pow(2, 160);  // 2^160 possible addresses
    
    // Calculate time needed
    double seconds_needed = total_addresses / addresses_per_second;
    double minutes_needed = seconds_needed / 60;
    double hours_needed = minutes_needed / 60;
    double days_needed = hours_needed / 24;
    double years_needed = days_needed / 365.25;
    
    printf("\n=== Time Analysis ===\n");
    printf("Total possible addresses: 2^160 (%.2e)\n", total_addresses);
    printf("Your generation speed: %ld addresses/second\n", addresses_per_second);
    printf("\nTime needed to generate all addresses:\n");
    printf("Seconds: %.2e\n", seconds_needed);
    printf("Minutes: %.2e\n", minutes_needed);
    printf("Hours:   %.2e\n", hours_needed);
    printf("Days:    %.2e\n", days_needed);
    printf("Years:   %.2e\n", years_needed);
    
    // Add some perspective
    printf("\nFor perspective:\n");
    printf("- Age of the universe is about 13.8 billion years (1.38e10)\n");
    printf("- Your computer would need %.2e times the age of the universe\n", 
           years_needed / (13.8e9));
    
    return total_addresses;  // Return this for use in collision analysis
}

void print_scaling_analysis(double total_addresses, long current_addr_per_second) {
    printf("\n=== Scaling Analysis ===\n");
    
    // Hardware scaling scenarios
    const long computers_scenarios[] = {1000, 1000000, 1000000000}; // 1K, 1M, 1B computers
    const long speed_improvements[] = {10, 100, 1000}; // 10x, 100x, 1000x faster
    
    printf("Hardware Scaling Scenarios:\n");
    printf("1. Multiple Computers (current speed: %.2e addr/s)\n", (double)current_addr_per_second);
    for (int i = 0; i < 3; i++) {
        double total_speed = current_addr_per_second * computers_scenarios[i];
        double years_needed = (total_addresses / total_speed) / (365.25 * 24 * 3600);
        printf("   - With %.2e computers: %.2e addr/s (%.2e universe ages)\n",
               (double)computers_scenarios[i], total_speed, years_needed / (13.8e9));
    }
    
    printf("\n2. Speed Improvements (single computer)\n");
    for (int i = 0; i < 3; i++) {
        double improved_speed = current_addr_per_second * speed_improvements[i];
        double years_needed = (total_addresses / improved_speed) / (365.25 * 24 * 3600);
        printf("   - %ld times faster: %.2e addr/s (%.2e universe ages)\n",
               speed_improvements[i], improved_speed, years_needed / (13.8e9));
    }
    
    // Combined best case scenario
    double best_case_speed = current_addr_per_second * computers_scenarios[2] * speed_improvements[2];
    double best_case_years = (total_addresses / best_case_speed) / (365.25 * 24 * 3600);
    
    printf("\n3. Best Case Scenario (1B computers, 1000x faster each):\n");
    printf("   - Total speed: %.2e addr/s\n", best_case_speed);
    printf("   - Still needs %.2e universe ages\n", best_case_years / (13.8e9));
    
    // Quantum computing scenario
    printf("\n4. Theoretical Quantum Computing Scenario:\n");
    printf("   - If quantum computers could test 1 trillion (1e12) addresses per second:\n");
    double quantum_years = (total_addresses / 1e12) / (365.25 * 24 * 3600);
    printf("   - Still would take %.2e years (%.2e universe ages)\n",
           quantum_years, quantum_years / (13.8e9));
}

void print_advanced_analysis(double total_addresses, long addresses_per_second) {
    printf("\n=== Advanced Statistical Analysis ===\n");
    
    // Energy analysis - updated with more accurate CPU utilization
    const double watts_per_cpu = 65.0;  // Average CPU power consumption
    const double cpu_utilization = 0.8;  // Estimated CPU utilization for this task
    const double actual_power = watts_per_cpu * cpu_utilization;
    const double joules_per_address = (actual_power / addresses_per_second);
    double daily_energy = addresses_per_second * 86400 * joules_per_address;
    double daily_kwh = daily_energy / 3600000;
    double monthly_kwh = daily_kwh * 30;
    double yearly_kwh = daily_kwh * 365;
    
    printf("Energy Consumption Analysis:\n");
    printf("- CPU power consumption: %.2f watts (%.0f%% utilization)\n", 
           watts_per_cpu, cpu_utilization * 100);
    printf("- Actual power used: %.2f watts\n", actual_power);
    printf("- Energy per address: %.8f joules\n", joules_per_address);
    printf("- Daily energy usage: %.2f kWh\n", daily_kwh);
    printf("- Monthly energy usage: %.2f kWh\n", monthly_kwh);
    printf("- Yearly energy usage: %.2f kWh\n", yearly_kwh);
    printf("- Equivalent to powering %.3f homes per day\n", daily_kwh / 30); // Average home uses 30 kWh/day
    printf("- Monthly electricity cost: $%.2f (at $0.12/kWh)\n", monthly_kwh * 0.12);
    printf("- Yearly electricity cost: $%.2f\n", yearly_kwh * 0.12);
    
    // Carbon footprint with updated calculations
    const double kg_co2_per_kwh = 0.385; // EPA average US grid carbon intensity
    double yearly_carbon = yearly_kwh * kg_co2_per_kwh;
    printf("\nCarbon Footprint:\n");
    printf("- Yearly CO2 emissions: %.2f kg\n", yearly_carbon);
    printf("- Equivalent to %.2f trees needed for carbon offset\n", yearly_carbon / 21.0);

    // Space-time complexity
    printf("\nComputational Complexity:\n");
    printf("- Time complexity: O(2^160) for exhaustive search\n");
    printf("- Space complexity: O(1) for current implementation\n");
    printf("- Memory usage per thread: ~%.2f KB\n", sizeof(ThreadData) / 1024.0);
    
    // Statistical distribution analysis with more detail
    printf("\nAddress Space Distribution:\n");
    printf("- Uniform distribution across 2^160 space\n");
    printf("- Each address occupies %.2e fraction of total space\n", 1.0 / total_addresses);
    printf("- Entropy: 160 bits\n");
    
    // Network comparison with updated hashrate
    const double bitcoin_hashrate = 500e18; // Updated Bitcoin network hashrate (500 EH/s)
    printf("\nBitcoin Network Comparison:\n");
    printf("- Current network hashrate: %.2e H/s\n", bitcoin_hashrate);
    printf("- Your address generation rate: %.2e addr/s\n", (double)addresses_per_second);
    printf("- Network is %.2e times more powerful for mining\n", bitcoin_hashrate / addresses_per_second);
    
    // Security margin analysis with more detail
    double security_margin = log2(total_addresses);
    printf("\nSecurity Margin Analysis:\n");
    printf("- Effective security bits: %.2f\n", security_margin);
    printf("- Security margin above 128-bit: %.2f bits\n", security_margin - 128);
    printf("- Quantum security margin: %.2f bits\n", security_margin / 2); // Grover's algorithm effect
    
    // Future projections with more realistic Moore's Law
    printf("\nFuture Technology Projections:\n");
    printf("- Moore's Law projection (doubling every 2 years):\n");
    double moores_law_years = log2(total_addresses / addresses_per_second) * 2;
    printf("  * Years until significant threat: %.2e\n", moores_law_years);
    printf("  * Note: Moore's Law is slowing down in recent years\n");
    
    // Collision resistance with improved calculations
    double birthday_bound = sqrt(total_addresses);
    double birthday_years = (birthday_bound / addresses_per_second) / (365.25 * 24 * 3600);
    printf("\nCollision Resistance:\n");
    printf("- Birthday bound: %.2e addresses\n", birthday_bound);
    printf("- Time to reach birthday bound: %.2e years\n", birthday_years);
    printf("- Probability of collision within 1 year: %.2e\n", 
           1.0 - exp(-(pow(addresses_per_second * 365.25 * 24 * 3600, 2) / (2 * total_addresses))));
    
    // Heat death comparison fixed
    const double heat_death_years = 1e100;
    double total_years_needed = (total_addresses / addresses_per_second) / (365.25 * 24 * 3600);
    printf("\nCosmic Perspective:\n");
    printf("- Universe heat death: ~1e100 years\n");
    printf("- Your task would take %.2e years\n", total_years_needed);
    printf("- Ratio to heat death timeline: %.2e\n", total_years_needed / heat_death_years);
}

void print_bruteforce_analysis(double total_addresses, long addresses_per_second, int num_threads) {
    printf("\n=== Brute Force Strategy Analysis ===\n");
    
    // Random vs Sequential Analysis
    printf("Random vs Sequential Search Strategy:\n");
    printf("- Current approach: Random sampling of address space\n");
    printf("- Advantage: Equal probability for all addresses\n");
    printf("- Memory efficiency: No need to store previous attempts\n");
    
    // Coverage Analysis
    double addresses_per_year = addresses_per_second * 365.25 * 24 * 3600;
    double space_coverage_year = (addresses_per_year / total_addresses) * 100;
    
    printf("\nAddress Space Coverage:\n");
    printf("- Addresses generated per year: %.2e\n", addresses_per_year);
    printf("- Percentage of total space covered per year: %.2e%%\n", space_coverage_year);
    printf("- Years to cover 0.0001%% of space: %.2e\n", 
           (total_addresses * 0.000001) / addresses_per_year);
    
    // Probability Distribution
    printf("\nProbability Distribution:\n");
    printf("- Distribution type: Uniform random sampling\n");
    printf("- Replacement strategy: With replacement (same address can be generated multiple times)\n");
    printf("- Collision probability follows birthday paradox principles\n");
    
    // Search Space Reduction Strategies
    printf("\nPotential Search Space Reduction Strategies:\n");
    printf("1. Pattern-based reduction:\n");
    printf("   - Valid checksum addresses only: reduces by ~2^32\n");
    printf("   - Valid public key format: reduces by ~2^8\n");
    printf("   - Total reduction: ~2^40 of search space\n");
    
    // Time to find specific patterns
    double reduced_space = total_addresses / pow(2, 40);
    double time_to_pattern = reduced_space / addresses_per_second;
    
    printf("\nPattern-based Search Times:\n");
    printf("- Time to find address with specific pattern:\n");
    printf("  * Starting with '1': %.2e years\n", time_to_pattern / (365.25 * 24 * 3600));
    printf("  * Vanity address (3 chars): %.2e years\n", 
           time_to_pattern * pow(58, 3) / (365.25 * 24 * 3600));
    
    // Parallel Search Strategies
    printf("\nParallel Search Optimization:\n");
    printf("1. Space Partitioning:\n");
    printf("   - Current: Random sampling across full space\n");
    printf("   - Alternative: Divide space into %d ranges\n", num_threads);
    printf("   - Trade-off: Less randomness, potentially uneven distribution\n");
    
    // Memory Trade-offs
    const double memory_per_address = 25 + 34; // 25 bytes address + 34 bytes metadata
    double addresses_storable = (1ULL << 30) / memory_per_address; // 1GB of RAM
    
    printf("\nMemory-Time Trade-offs:\n");
    printf("- Memory required to store 1 billion addresses: %.2f GB\n", 
           (1e9 * memory_per_address) / (1ULL << 30));
    printf("- Addresses storable in 1GB RAM: %.2e\n", addresses_storable);
    printf("- Time to fill 1GB lookup table: %.2f minutes\n", 
           (addresses_storable / addresses_per_second) / 60);
    
    // Advanced Search Optimizations
    printf("\nAdvanced Search Optimizations:\n");
    printf("1. GPU Acceleration Potential:\n");
    printf("   - Estimated speedup: 100-1000x\n");
    printf("   - Memory bandwidth limited\n");
    
    printf("\n2. ASIC Implementation Potential:\n");
    printf("   - Estimated speedup: 1000-10000x\n");
    printf("   - Custom hardware for RIPEMD160 + SHA256\n");
    
    printf("\n3. Quantum Search Impact:\n");
    printf("   - Grover's algorithm speedup: Square root of search space\n");
    printf("   - Effective search space: 2^80 instead of 2^160\n");
    printf("   - Still requires %.2e years with 1 trillion qubits\n",
           sqrt(total_addresses) / 1e12 / (365.25 * 24 * 3600));
    
    // Statistical Success Rates
    printf("\nSuccess Rate Analysis:\n");
    printf("1. Finding any valid address:\n");
    printf("   - Immediate (current implementation)\n");
    
    printf("\n2. Finding specific target address:\n");
    printf("   - Probability per attempt: %.2e\n", 1.0 / total_addresses);
    printf("   - Attempts for 50%% chance: %.2e\n", 0.693 * total_addresses);
    printf("   - Attempts for 99.9%% chance: %.2e\n", 6.908 * total_addresses);
    
    // Optimization Recommendations
    printf("\nOptimization Recommendations:\n");
    printf("1. Implementation Level:\n");
    printf("   - Use batch processing for key generation\n");
    printf("   - Optimize cryptographic operations\n");
    printf("   - Reduce memory allocations\n");
    
    printf("\n2. Architecture Level:\n");
    printf("   - Distribute work across GPUs\n");
    printf("   - Use specialized hardware for hashing\n");
    printf("   - Implement intelligent work distribution\n");
}

int main() {
    int num_processes = 12;
    int num_threads = 8;
    int duration = 5;
    
    // Initialize shared memory before forking
    shared_mem = create_shared_memory();
    if (!shared_mem) {
        fprintf(stderr, "Failed to create shared memory\n");
        return 1;
    }

    printf("Starting multi-process benchmark with %d processes, %d threads each...\n", 
           num_processes, num_threads);
    
    // Store process IDs
    pid_t* pids = malloc(num_processes * sizeof(pid_t));
    
    for (int i = 0; i < num_processes - 1; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            run_benchmark(num_threads, duration, i + 1);
            exit(0);
        } else {
            pids[i] = pid;
        }
    }
    
    // Parent process runs benchmark
    run_benchmark(num_threads, duration, 0);
    
    // Wait for all child processes
    for (int i = 0; i < num_processes - 1; i++) {
        waitpid(pids[i], NULL, 0);
    }
    
    // Get the final rate
    long addresses_per_second = shared_mem->total_addresses / duration;
    
    // Print final total across all processes
    printf("\n=== Final Results ===\n");
    printf("Total addresses generated across all processes: %ld\n", shared_mem->total_addresses);
    printf("Average generation rate: %.2f addresses per second\n", 
           shared_mem->total_addresses / (double)duration);
    
    // Add time analysis and get total possible addresses
    double total_possible_addresses = print_time_analysis(addresses_per_second);
    
    // Add collision probability analysis
    print_collision_probability(total_possible_addresses, addresses_per_second);
    
    // After the existing analyses, add:
    print_scaling_analysis(total_possible_addresses, addresses_per_second);
    print_advanced_analysis(total_possible_addresses, addresses_per_second);
    print_bruteforce_analysis(total_possible_addresses, addresses_per_second, num_threads);
    
    // Cleanup
    if (shared_mem != NULL) {
        pthread_mutex_destroy(&shared_mem->mutex);
        munmap(shared_mem, sizeof(SharedMemory));
    }
    shm_unlink("/bitcoin_benchmark");
    free(pids);
    
    return 0;
}
