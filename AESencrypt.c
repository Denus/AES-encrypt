#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <openssl/aes.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

// Function to encrypt a file using AES-256
void encryptFile(const char* inputFilePath, const char* outputFilePath, const char* key) {
    FILE* inputFile = fopen(inputFilePath, "rb");
    FILE* outputFile = fopen(outputFilePath, "wb");

    if (!inputFile || !outputFile) {
        perror("Error opening files");
        exit(1);
    }

    AES_KEY aesKey;
    AES_set_encrypt_key((const unsigned char*)key, AES_KEY_SIZE * 8, &aesKey);

    unsigned char inputBlock[AES_BLOCK_SIZE];
    unsigned char outputBlock[AES_BLOCK_SIZE];

    size_t bytesRead;

    while ((bytesRead = fread(inputBlock, 1, AES_BLOCK_SIZE, inputFile)) > 0) {
        AES_encrypt(inputBlock, outputBlock, &aesKey);
        fwrite(outputBlock, 1, bytesRead, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);
}

// Function to decrypt a file using AES-256
void decryptFile(const char* inputFilePath, const char* outputFilePath, const char* key) {
    FILE* inputFile = fopen(inputFilePath, "rb");
    FILE* outputFile = fopen(outputFilePath, "wb");

    if (!inputFile || !outputFile) {
        perror("Error opening files");
        exit(1);
    }

    AES_KEY aesKey;
    AES_set_decrypt_key((const unsigned char*)key, AES_KEY_SIZE * 8, &aesKey);

    unsigned char inputBlock[AES_BLOCK_SIZE];
    unsigned char outputBlock[AES_BLOCK_SIZE];

    size_t bytesRead;

    while ((bytesRead = fread(inputBlock, 1, AES_BLOCK_SIZE, inputFile)) > 0) {
        AES_decrypt(inputBlock, outputBlock, &aesKey);
        fwrite(outputBlock, 1, bytesRead, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);
}

// GTK callback function for encrypt button
void on_encrypt_clicked(GtkButton *button, gpointer user_data) {
    const char *inputFilePath = gtk_entry_get_text(GTK_ENTRY(user_data));
    const char *outputFilePath = "encrypted_output.enc"; // You can set the output file name
    const char *encryptionKey = "ThisIsASecretKey123"; // 256-bit key

    encryptFile(inputFilePath, outputFilePath, encryptionKey);
    gtk_label_set_text(GTK_LABEL(user_data), "File encrypted successfully.");
}

// GTK callback function for decrypt button
void on_decrypt_clicked(GtkButton *button, gpointer user_data) {
    const char *inputFilePath = gtk_entry_get_text(GTK_ENTRY(user_data));
    const char *outputFilePath = "decrypted_output.txt"; // You can set the output file name
    const char *encryptionKey = "ThisIsASecretKey123"; // 256-bit key

    decryptFile(inputFilePath, outputFilePath, encryptionKey);
    gtk_label_set_text(GTK_LABEL(user_data), "File decrypted successfully.");
}

int main(int argc, char* argv[]) {
    // GTK initialization
    gtk_init(&argc, &argv);

    GtkWidget *window;
    GtkWidget *vbox;
    GtkWidget *entry;
    GtkWidget *encryptButton;
    GtkWidget *decryptButton;
    GtkWidget *resultLabel;

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "File Encryption Program");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    vbox = gtk_vbox_new(FALSE, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(vbox), entry, TRUE, TRUE, 0);

    encryptButton = gtk_button_new_with_label("Encrypt File");
    g_signal_connect(encryptButton, "clicked", G_CALLBACK(on_encrypt_clicked), entry);
    gtk_box_pack_start(GTK_BOX(vbox), encryptButton, TRUE, TRUE, 0);

    decryptButton = gtk_button_new_with_label("Decrypt File");
    g_signal_connect(decryptButton, "clicked", G_CALLBACK(on_decrypt_clicked), entry);
    gtk_box_pack_start(GTK_BOX(vbox), decryptButton, TRUE, TRUE, 0);

    resultLabel = gtk_label_new("Status: ");
    gtk_box_pack_start(GTK_BOX(vbox), resultLabel, TRUE, TRUE, 0);

    gtk_widget_show_all(window);

    // Start GTK main loop
    gtk_main();

    return 0;
}
