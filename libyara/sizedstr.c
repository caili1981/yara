/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <yara/sizedstr.h>
#include <yara/strutils.h>

int sized_string_cmp(
  SIZED_STRING* s1,
  SIZED_STRING* s2)
{
  int cmp;
  int case_insensitive = \
      (s1->flags & SIZED_STRING_FLAGS_NO_CASE) ||
      (s2->flags & SIZED_STRING_FLAGS_NO_CASE);

  size_t i = 0;

  while (i < s1->length && i < s2->length)
  {
    uint8_t c1 = (uint8_t) s1->c_string[i];
    uint8_t c2 = (uint8_t) s2->c_string[i];

    if (case_insensitive)
      cmp = lowercase[c1] - lowercase[c2];
    else
      cmp = c1 - c2;

    if (cmp != 0)
      break;

    i++;
  }

  if (i == s1->length && i == s2->length)
    return 0;
  else if (i == s1->length)
    return -1;
  else if (i == s2->length)
    return 1;
  else if (cmp < 0)
    return -1;
  else
    return 1;
}


int sized_string_contains(
  SIZED_STRING* s1,
  SIZED_STRING* s2)
{
  int case_insensitive = \
      (s1->flags & SIZED_STRING_FLAGS_NO_CASE) ||
      (s2->flags & SIZED_STRING_FLAGS_NO_CASE);

  size_t i1 = 0;
  size_t i2 = 0;

  if (s2->length > s1->length) 
    return 0;  // s1 can't contain s2 because s2 is larger

  while(i1 < s1->length && i2 < s2->length)
  {
    uint8_t c1 = (uint8_t) s1->c_string[i1];
    uint8_t c2 = (uint8_t) s2->c_string[i2];

    int equals;

    if (case_insensitive)
      equals = lowercase[c1] == lowercase[c2];
    else
      equals = c1 == c2;

    if (equals) 
      i2++;
    else 
      i2 = 0;

    i1++;
  }

  return i2 == s2->length;
}



