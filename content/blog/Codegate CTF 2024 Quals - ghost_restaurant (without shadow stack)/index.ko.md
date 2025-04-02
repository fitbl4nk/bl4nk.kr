+++
title = "Codegate CTF 2024 Quals - ghost_restaurant (without shadow stack)"
date = "2024-08-28"
description = "Codegate CTF 2024 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "race condition", "tls"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/ghost_restaurant'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Structure
``` c
struct food {
    char name[0x40];
    long cook_time;
    long left_time;
}
```
이 외에도 사용되는 구조체가 몇개 있지만 문제 풀이에 중요한 구조체만 정리하였다.

### Concept
`oven`을 생성해서 선택하면 `cook_1928` 쓰레드가 생성되어 `food`를 `insert`하거나 `remove`할 수 있다.

`insert` 시 입력한 `cook_time`만큼의 시간이 지나면 `food`가 완성되며 이 때 시간을 감소시키고 시간이 다 지났는지 확인하는 과정은 `start_routine_16B1` 쓰레드를 통해 이루어진다.

## 0x01. Vulnerability
### Information leak
`cook_time`이 다 되어서든, `remove`를 해서든 `food`가 삭제될 때 다음과 같은 로직을 통해 메모리가 변경된다.
``` c
printf("Select food to remove in '%s':\n", oven->name);
__isoc99_scanf("%d", &tmp);
for ( i = tmp; i < food_count; ++i )
{
  food_next = food[i + 1];
  food_cur = food[i];
  memcpy(food_cur, food_next, 0x50);
}
```
이 때 `food[i + 1]`에 어떤 값이 있는지 확인하지 않고 무조건 `food[i]`로 복사를 해오기 때문에 `food[i + 1]`에 중요한 데이터가 있다면 leak이 가능하다.

### Race condition
`food`의 남은 시간을 체크하는 `start_routine_16B1`의 코드를 보면,
``` c
void __fastcall __noreturn start_routine_16B1(struct argument *a1)
{
  ...
  while ( 1 )
  {
    if ( *(__int64 *)arg->count > 0 )
    {
      for ( i = 0; i < *(_QWORD *)arg->count; ++i )
      {
        if ( arg->food[i].left_time > 0 )
        {
          food_tmp = &arg->food[i];
          if ( !--food_tmp->left_time )
          {
            printf("'%s' is ready!\n", arg->food[i].name);
            ...
            for ( j = i; j < *(_QWORD *)arg->count; ++j )
            {
              food_next = &arg->food[j + 1];
              food_cur = &arg->food[j];
              memcpy(food_cur, food_next, 0x50);
            }
            --*(_QWORD *)arg->count;
          }
        }
      }
    }
    sleep(1u);
  }
}
```
`left_time`이 `0`이 됐을 때 해당 `food` 구조체 이후의 구조체들을 한 칸씩 앞으로 땡겨주고 `food_count`를 감소시킨다.

이 외에 다른 방법으로도 `food`를 제거할 수 있는데 `cook_1928`의 코드를 보면,
``` c
void *__fastcall cook_1928(struct oven *a1)
{
  ...
  while ( 1 )
  {
    pthread_mutex_lock((pthread_mutex_t *)oven->mutex);
    while ( !LODWORD(oven->ready) )
      pthread_cond_wait((pthread_cond_t *)oven->cond, (pthread_mutex_t *)oven->mutex);
    ...
    __isoc99_scanf("%d", &choice);
    ...
    if ( choice == 2 )
    {
      printf("Select food to remove in '%s':\n", oven->name);
      ...
      __isoc99_scanf("%d", &tmp);
      if ( (int)tmp <= (__int64)__readfsqword(0xFFFFFE90) && (int)tmp > 0 )
      {
        LODWORD(tmp) = tmp - 1;
        for ( m = tmp; m < (__int64)__readfsqword(0xFFFFFE90); ++m )
        {
          food_cur = (struct food *)(__readfsqword(0) + 0x50LL * m - 0x160);
          food_next = (struct food *)(__readfsqword(0) + 0x50LL * (m + 1) - 0x160);
          memcpy(food_cur, food_next, 0x50);
        }
        __writefsqword(0xFFFFFE90, __readfsqword(0xFFFFFE90) - 1);
        goto LABEL_39;
      }
LABEL_19:
      puts("Invalid choice.");
      pthread_mutex_unlock((pthread_mutex_t *)oven->mutex);
    }
LABEL_39:
    pthread_mutex_unlock((pthread_mutex_t *)oven->mutex);
  }
  ...
}
```
현재 들어가있는 `food`의 목록을 출력해주고 `tmp`에 제거할 `food`의 인덱스를 받아서 삭제한 후 26번 라인의 `__writefsqword()`를 통해 `food_count` 값을 감소시킨다.

여기에서 발생하는 취약점은 `start_routine_16B1`에서 시간이 다 됐을 때 `food_count`를 감소시키는 코드가 critical section으로 관리되지 않는다.

따라서 `cook_1928`의 `remove` 로직과 동시에 실행될 수 있기 때문에 race condition이 발생한다.

|cook_1928|start_routine_16B1|
|: