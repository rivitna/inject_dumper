//---------------------------------------------------------------------------
#ifndef __LOG_H__
#define __LOG_H__
//---------------------------------------------------------------------------
// Открытие файла отчета
BOOL OpenLog(
  const TCHAR *pszLogPath,
  BOOL bAppend
  );
// Закрытие файла отчета
void CloseLog();
// Запись текста в файл отчета
unsigned int LogW(
  const wchar_t *pchText,
  unsigned int cchText = 0
  );
// Запись форматированного текста в файл отчета
unsigned int LogFmtW(
  const wchar_t *pszFormat,
  ...
  );
//---------------------------------------------------------------------------
#endif // __LOG_H__
