static_assert(__cplusplus >= 201703L);

int main() {
    return __DATE__[0] != 'r' || __TIME__[0] != 'r' || __TIMESTAMP__[0] != 'r';
}
