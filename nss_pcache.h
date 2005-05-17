/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define PIN_SUCCESS     0
#define PIN_NOMEMORY    1
#define PIN_SYSTEMERROR 2
#define PIN_NOSUCHTOKEN 3
#define PIN_INCORRECTPW 4

typedef struct Pk11PinStore Pk11PinStore;

int CreatePk11PinStore(Pk11PinStore **out, const char *tokenName, const char *pin);

int Pk11StoreGetPin(char **out, Pk11PinStore *store);

void DestroyPk11PinStore(Pk11PinStore *store);
