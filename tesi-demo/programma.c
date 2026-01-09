#include <stdio.h>

int main() {
    char nome[50];
    char cognome[40];
    int lunghezzaNome, lunghezzaCognome;
    int i;

    printf("Inserisci la lunghezza del nome: ");
    scanf("%d", &lunghezzaNome);

    getchar(); // rimuove il newline residuo

    printf("Inserisci il nome: ");
    for(i = 0; i < lunghezzaNome; i++) {
        scanf("%c", &nome[i]);
    }

    printf("Nome inserito: ");
    for(i = 0; i < lunghezzaNome; i++) {
        printf("%c", nome[i]);
    }
    printf("\n");

    printf("Inserisci la lunghezza del cognome: ");
    scanf("%d", &lunghezzaCognome);

    getchar(); // rimuove il newline residuo

    printf("Inserisci il cognome: ");
    for(i = 0; i < lunghezzaCognome; i++) {
        scanf("%c", &cognome[i]);
    }

    printf("Cognome inserito: ");
    for(i = 0; i < lunghezzaCognome; i++) {
        printf("%c", cognome[i]);
    }
    printf("\n");

    return 0;
}