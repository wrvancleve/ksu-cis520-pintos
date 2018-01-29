File Additions:
alarm-mega.ck: Alarm with check_alarm (70);

File Changes:
tests.c: Added line {"alarm-mega", test_alarm_mega}, to test struct.
tests.h: Added line extern test_func test_alarm_mega;
Rubric.alarm: Added 4   alarm-mega
Make.tests: Added alarm-mega test name
alarm-wait.c: Added mega test function. void
test_alarm_mega (void) 
{
  test_sleep (5, 70);
}
