// Leak detection is off for every fizz fuzz target (SPEC §6.2 item 15):
// leaks are not the bug class this fleet fuzzes for. ASan and UBSan stay on.
extern "C" int __lsan_is_turned_off() {
  return 1;
}
