# image-viewer (ctfcup) — writeup & exploit

Цель: `nc instances.ctfcup.online 1337`, получить `ctfcup{...}`.

```bash
python3 exploit.py instances.ctfcup.online 1337
# если инстанс требует токен первой строкой:
python3 exploit.py instances.ctfcup.online 1337 --token BTG0ZSUL8I78E6C0M650RT6ZIXAS7M3Z
# интерактивный shell (если флаг лежит не в /flag*):
python3 exploit.py instances.ctfcup.online 1337 -i
```

Только стандартная библиотека Python 3, зависимостей нет.

## Уязвимости

1. **Чтение кучи.** Проверка границ превью:
   `offset + length <= width * height * (depth / 8)`.
   `X-Preview-Depth` — произвольное число (`2000000000` → `(depth+7)>>3` огромно),
   проверка проходит, и сервер отдаёт до 1024 байт по `view + offset`.

2. **Переполнение кучи.** RLE-декодер Targa (`read_rle_data`) выделяет `w*h*3`
   байт, но пишет целые чанки, не проверяя курсор: последний raw-чанк
   (до 128 пикселей) пишет `128*3 = 384` байта за границу.

3. **Почему (2) вообще попадает в цель.** `X-Preview-Size` (S) используется для
   двух `malloc(S)`, которые освобождаются **до** аллокации буферов картинки:

   ```
   body(0x10000) -> tmp1(S) -> tmp2(S) -> filter(0x188)
   free(tmp2); free(tmp1)
   view = malloc(w*h*3)   # забирает tmp1
   temp = malloc(w*h*3)   # забирает tmp2   (нужно S == w*h*3)
   ... RLE-декод пишет в temp ...   # переполнение бьёт ровно в filter
   ```

   Объект фильтра стоит ровно на один чанк выше `temp`. В конце запроса
   вызывается виртуальный метод:

   ```asm
   mov  rax, [rbp]        ; rbp = filter
   mov  edx, gamma
   mov  esi, scale
   mov  rdi, rbp
   call [rax+0x10]
   ```

   `rdi == rbp == filter`, поэтому подменяем vtable на `leave; ret` —
   стек уезжает в перезаписанный объект, дальше обычный ROP:
   `execve("/bin/sh", NULL, NULL)`. `rdx = 0` берётся из `X-Gamma: 0`.
   fd 0/1/2 у форкнутого ребёнка — это сокет, так что шелл сразу в соединении.

## Утечка адресов

Сервер форкается на каждое соединение из одного и того же родительского
процесса, поэтому раскладка кучи байт-в-байт повторяется между соединениями.
Первый (безопасный) запрос читает кучу и в ответе на смещении `0x80`
лежит объект фильтра:

```
+0x00  vtable        -> PIE base = vtable - 0x206db8 (WarmFilter)
+0x08  указатель на view-буфер  (первый malloc(X-Preview-Size))
+0x10  указатель на temp-буфер  (второй malloc(X-Preview-Size))
```

Оба запроса (утечка и эксплойт) имеют одинаковую длину и одинаковые заголовки,
поэтому куча в них идентична.

## Гаджеты (static PIE, vaddr == file offset)

| что | адрес |
|---|---|
| WarmFilter vtable | `0x206db8` |
| `leave ; ret` | `0x0cf7b1` |
| `pop rdi ; ret` | `0x1cca4` |
| `pop rsi ; ret` | `0x239af` |
| `pop rax ; ret` | `0x3b4aa` |
| `syscall` (в обёртке send) | `0x155ed5` |

## Файлы

* `exploit.py` — готовый эксплойт.
* `probe.py`, `raw.py`, `heap.py`, `recon.py` — вспомогательные скрипты,
  которыми исследовался бинарник/куча.
