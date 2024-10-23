#include <stdio.h>

int main() {
    int N;
    scanf("%d", &N);

    int A[N];
    for (int i = 0; i < N; i++) {
        scanf("%d", &A[i]);
    }

    int operations = 0;
    for (int i = 0; i < N / 2; i++) {
        int diff = abs(A[i] - A[N - i - 1]);
        operations += diff;
    }

    printf("%d\n", operations);
    return 0;
}