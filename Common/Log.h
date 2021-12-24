//---------------------------------------------------------------------------
#ifndef __LOG_H__
#define __LOG_H__
//---------------------------------------------------------------------------
// �������� ����� ������
BOOL OpenLog(
  const TCHAR *pszLogPath,
  BOOL bAppend
  );
// �������� ����� ������
void CloseLog();
// ������ ������ � ���� ������
unsigned int LogW(
  const wchar_t *pchText,
  unsigned int cchText = 0
  );
// ������ ���������������� ������ � ���� ������
unsigned int LogFmtW(
  const wchar_t *pszFormat,
  ...
  );
//---------------------------------------------------------------------------
#endif // __LOG_H__
