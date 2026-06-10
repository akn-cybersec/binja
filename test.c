// test_binja.c - Comprehensive test binary for binja analysis tool
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

// Global variables for testing
char global_data[] = "Sensitive data in .data section";
const char rodata_string[] = "Constant string in .rodata section";
static int static_counter = 0;

// Function declarations
void secret_function(void);
void win_function(void);
void vulnerable_function(char *input);
void recursive_function(int depth);
void indirect_call(void (*func)(void));
int calculate_sum(int a, int b, int c, int d);
void print_flag(void);

// Secret function - should be found by xrefs
void secret_function(void) {
    printf("[SECRET] You found the secret function!\n");
    printf("[SECRET] Flag: BINJA{S3cr3t_Funct10n_D1sc0v3r3d}\n");
}

// Win function - target for patching examples
void win_function(void) {
    printf("[WIN] Congratulations! You reached the win function!\n");
    printf("[WIN] This is the intended success path.\n");
}

// Vulnerable function - demonstrates buffer overflow
void vulnerable_function(char *input) {
    char buffer[64];
    printf("[VULN] Copying input of length %zu bytes\n", strlen(input));
    strcpy(buffer, input);  // Vulnerable to buffer overflow
    printf("[VULN] Buffer contains: %s\n", buffer);
}

// Recursive function for testing
void recursive_function(int depth) {
    if (depth <= 0) {
        printf("[RECUR] Base case reached at depth %d\n", depth);
        return;
    }
    printf("[RECUR] Depth: %d\n", depth);
    recursive_function(depth - 1);
}

// Indirect call example
void indirect_call(void (*func)(void)) {
    printf("[INDIRECT] Calling function pointer at %p\n", (void*)func);
    func();
}

// Calculate sum with multiple parameters
int calculate_sum(int a, int b, int c, int d) {
    int result = a + b + c + d;
    printf("[CALC] %d + %d + %d + %d = %d\n", a, b, c, d, result);
    return result;
}

// Print flag function
void print_flag(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║                    BINJA TEST FLAG                   ║\n");
    printf("║                                                      ║\n");
    printf("║  BINJA{ELF_Analyzer_Parsing_Disassembly_Patching}   ║\n");
    printf("║                                                      ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n");
}

// Function that calls multiple others
void dispatch_commands(int cmd) {
    switch(cmd) {
        case 1:
            win_function();
            break;
        case 2:
            secret_function();
            break;
        case 3:
            print_flag();
            break;
        default:
            printf("[DISPATCH] Unknown command: %d\n", cmd);
    }
}

// Main function
int main(int argc, char *argv[]) {
    int choice;
    char user_input[256];
    
    printf("\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("         BINJA TEST BINARY - REVERSE ENGINEERING       \n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("\n");
    
    printf("[MAIN] Program started\n");
    printf("[MAIN] Global data: %s\n", global_data);
    printf("[MAIN] Read-only data: %s\n", rodata_string);
    printf("[MAIN] Address of main: %p\n", main);
    printf("[MAIN] Address of win_function: %p\n", win_function);
    printf("[MAIN] Address of secret_function: %p\n", secret_function);
    printf("[MAIN] Address of vulnerable_function: %p\n", vulnerable_function);
    printf("[MAIN] Address of recursive_function: %p\n", recursive_function);
    printf("[MAIN] Address of print_flag: %p\n", print_flag);
    printf("\n");
    
    // Test recursive function
    printf("[TEST] Testing recursive function:\n");
    recursive_function(3);
    printf("\n");
    
    // Test indirect call
    printf("[TEST] Testing indirect call:\n");
    indirect_call(win_function);
    printf("\n");
    
    // Test calculate sum
    printf("[TEST] Testing calculate sum:\n");
    int sum = calculate_sum(10, 20, 30, 40);
    printf("[TEST] Sum result: %d\n", sum);
    printf("\n");
    
    // Test dispatch
    printf("[TEST] Testing dispatch:\n");
    dispatch_commands(1);
    dispatch_commands(2);
    printf("\n");
    
    // Interactive menu
    while(1) {
        printf("\n");
        printf("┌─────────────────────────────────────────────────┐\n");
        printf("│              BINJA TEST MENU                    │\n");
        printf("├─────────────────────────────────────────────────┤\n");
        printf("│ 1. Call win_function()                          │\n");
        printf("│ 2. Call secret_function()                       │\n");
        printf("│ 3. Call print_flag()                            │\n");
        printf("│ 4. Test vulnerable function (buffer overflow)   │\n");
        printf("│ 5. Exit                                         │\n");
        printf("└─────────────────────────────────────────────────┘\n");
        printf("Choice: ");
        
        if (scanf("%d", &choice) != 1) {
            break;
        }
        getchar(); // consume newline
        
        switch(choice) {
            case 1:
                win_function();
                break;
            case 2:
                secret_function();
                break;
            case 3:
                print_flag();
                break;
            case 4:
                printf("Enter input for vulnerable function: ");
                fgets(user_input, sizeof(user_input), stdin);
                user_input[strcspn(user_input, "\n")] = 0;
                vulnerable_function(user_input);
                break;
            case 5:
                printf("[MAIN] Exiting...\n");
                return 0;
            default:
                printf("[MAIN] Invalid choice: %d\n", choice);
        }
    }
    
    return 0;
}