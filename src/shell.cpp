/*
 *  Raster Steganography Win32 Application used to conceal a binary message
 *  (which can be a file of any type) within a PNG image file, and then
 *  extract the message from that image file.
 *
 *  Copyright (C) 2026  Javad Bayat
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _CRT_SECURE_NO_WARNINGS

#include "core.h"
#include <shellapi.h>
#include <ShObjIdl.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <math.h>
#include <string>

using namespace RasterSteganography;

HANDLE g_hScreenBuffer;

#define MY_OPERATION_GROUP 1

#define MY_RADIO_BUTTONS 2

#define MY_OPTION_ENCODE 1
#define MY_OPTION_DECODE 2
#define MY_OPTION_INFO 3

#define REGULAR_TEXT_ATTR (FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED)

typedef HRESULT ( STDAPICALLTYPE * PFN_CREATE_STREAM_ON_FILE )( LPCWSTR pszFile, DWORD grfMode, DWORD dwAttributes, BOOL fCreate, IStream *pstmTemplate, IStream **ppstm );

void printSize(PWSTR pwszFormat, ULONGLONG ullSize)
{
    const PWSTR sizeTags[] = { L"TB", L"GB", L"MB", L"KB", L"Bytes" };
    ULONGLONG multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    BYTE i;

	for (i = 0; i < CELEMS(sizeTags); i++)
    {
		if (ullSize >= multiplier)
            break;

		multiplier /= 1024;
    }

	wprintf(pwszFormat, (float) ullSize / multiplier, sizeTags[i]);
}

HRESULT CALLBACK ProgressSink(LONG lPixelOffset, LONG lPixelCount, LENGTH_PREFIX cbDataOffset, LENGTH_PREFIX cbDataLength, LPVOID pvContext)
{
	static int currentProgress;

	int progress = (int)(floor((double) cbDataOffset / (double) cbDataLength * 100.00));
	if (progress > currentProgress)
	{
		currentProgress = progress;

		if (GetKeyState( VK_SCROLL ) & 1)
			return S_FALSE;

		CONSOLE_SCREEN_BUFFER_INFO csbi;

		if (!GetConsoleScreenBufferInfo( g_hScreenBuffer, &csbi ))
			return HRESULT_FROM_WIN32( GetLastError() );

		csbi.dwCursorPosition.X = 0;
		csbi.dwCursorPosition.Y -= 2;
		if (!SetConsoleCursorPosition( g_hScreenBuffer, csbi.dwCursorPosition ))
			return HRESULT_FROM_WIN32( GetLastError() );

		if (!SetConsoleTextAttribute( g_hScreenBuffer, FOREGROUND_GREEN ))
			return HRESULT_FROM_WIN32( GetLastError() );

		wprintf( L"%ld out of %ld pixels affected\n", lPixelOffset, lPixelCount );
		wprintf( L"Overall Progress: %d%%\n", currentProgress );

		if (!SetConsoleTextAttribute( g_hScreenBuffer, REGULAR_TEXT_ATTR ))
			return HRESULT_FROM_WIN32( GetLastError() );
	}

	return S_OK;
}

int wmain(int argc, WCHAR *argv[])
{
	SetConsoleTitle( L"Steganography" );

	g_hScreenBuffer = CreateFile( L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL );
	if (g_hScreenBuffer == INVALID_HANDLE_VALUE)
	{
        wprintf(L"Failed to open a handle to console output.\n");
        wprintf(L"Error code: %d\n", GetLastError());
		_getch();
		return 1;
	}

	SetConsoleTextAttribute( g_hScreenBuffer, REGULAR_TEXT_ATTR );
	
	HRESULT hr = OleInitialize( NULL );
	if (FAILED(hr))
	{
		SetConsoleTextAttribute( g_hScreenBuffer, FOREGROUND_RED );
		wprintf(L"Failed to initialize OLE.");
		wprintf(L"Error code: 0x%08lx\n", hr);
		SetConsoleTextAttribute( g_hScreenBuffer, REGULAR_TEXT_ATTR );

		CloseHandle(g_hScreenBuffer);
		return 1;
	}

	IFileOpenDialog *pfodSource = NULL;
	IFileSaveDialog *pfsdDestination = NULL;
	IFileDialogCustomize *pfdc = NULL;
	IShellItem *psiImage = NULL, *psiSecretMessage = NULL, *psiResult = NULL;
	PWSTR pwszFilePath = NULL;
	HMODULE hShellLibrary = NULL;
	
	try
	{
		hShellLibrary = LoadLibrary( L"shlwapi.dll" );
		if (!hShellLibrary)
			_com_issue_error(HRESULT_FROM_WIN32(GetLastError()));

		PFN_CREATE_STREAM_ON_FILE pfnSHCreateStreamOnFileEx = (PFN_CREATE_STREAM_ON_FILE)(GetProcAddress( hShellLibrary, "SHCreateStreamOnFileEx" ));
		if (!pfnSHCreateStreamOnFileEx)
			_com_issue_error(HRESULT_FROM_WIN32(GetLastError()));

		hr = CoCreateInstance( CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_IFileOpenDialog, (PVOID *) &pfodSource );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfodSource->SetTitle( L"Image File" );
		if (FAILED(hr))
			_com_issue_error(hr);

		COMDLG_FILTERSPEC rgDialogFilters[] = {
			{ L"Bitmap Files (*.bmp;*.dib)", L"*.bmp;*.dib" },
			{ L"PNG (*.png)", L"*.png" },
			{ L"GIF (*.gif)", L"*.gif" },
			{ L"JPEG (*.jpg;*.jpeg;*.jpe;*.jfif)", L"*.jpg;*.jpeg;*.jpe;*.jfif" },
			{ L"TIFF (*.tif;*.tiff)", L"*.tif;*.tiff" },
			{ L"All Image Files", L"*.bmp;*.dib;*.png;*.gif;*.jpg;*.jpeg;*.jpe;*.jfif;*.tif;*.tiff" },
			{ L"All Files", L"*.*" }
		};

		hr = pfodSource->SetFileTypes( CELEMS(rgDialogFilters), rgDialogFilters );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfodSource->SetFileTypeIndex(6);
		if (FAILED(hr))
			_com_issue_error(hr);

		FILEOPENDIALOGOPTIONS dwOptions = 0;
		hr = pfodSource->GetOptions( &dwOptions );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfodSource->SetOptions( dwOptions | FOS_FORCEFILESYSTEM );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfodSource->QueryInterface( IID_IFileDialogCustomize, (PVOID *) &pfdc );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfdc->StartVisualGroup( MY_OPERATION_GROUP, L"&Operation:" );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfdc->AddRadioButtonList( MY_RADIO_BUTTONS );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfdc->AddControlItem( MY_RADIO_BUTTONS, MY_OPTION_ENCODE, L"Encode" );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfdc->AddControlItem( MY_RADIO_BUTTONS, MY_OPTION_DECODE, L"Decode" );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfdc->AddControlItem( MY_RADIO_BUTTONS, MY_OPTION_INFO, L"Info" );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfdc->EndVisualGroup();
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfdc->SetSelectedControlItem( MY_RADIO_BUTTONS, MY_OPTION_ENCODE );
		if (FAILED(hr))
			_com_issue_error(hr);

		hr = pfodSource->Show( GetConsoleWindow() );
		if (FAILED(hr))
			_com_issue_error(hr);

		DWORD dwUserChoice = 0;
		hr = pfdc->GetSelectedControlItem( MY_RADIO_BUTTONS, &dwUserChoice );
		if (FAILED(hr))
			_com_issue_error(hr);

		switch (dwUserChoice)
		{
		case MY_OPTION_INFO :
			{
				hr = pfodSource->GetResult( &psiImage );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = psiImage->GetDisplayName( SIGDN_FILESYSPATH, &pwszFilePath );
				if (FAILED(hr))
					_com_issue_error(hr);

				WIA::IImageFilePtr pifCarrier("WIA.ImageFile");

				wprintf( L"Loading image file '%s'...\n", pwszFilePath );
				pifCarrier->LoadFile( pwszFilePath );

				wprintf( L"Image Width: %ld\n", pifCarrier->Width );
				wprintf( L"Image Height: %ld\n", pifCarrier->Height );
				printSize( L"Image Capacity: %.2f%s\n", GetImageCapacity64( pifCarrier, NULL ) );

				break;
			}
		case MY_OPTION_ENCODE :
			{
				hr = pfodSource->GetResult( &psiImage );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = psiImage->GetDisplayName( SIGDN_FILESYSPATH, &pwszFilePath );
				if (FAILED(hr))
					_com_issue_error(hr);

				WIA::IImageFilePtr pifCarrier("WIA.ImageFile");

				pifCarrier->LoadFile( pwszFilePath );
				wprintf( L"Loaded image file '%s'...\n", pwszFilePath );

				CoTaskMemFree( pwszFilePath );
				pwszFilePath = NULL;

				pfodSource->Release();
				pfodSource = NULL;

				hr = CoCreateInstance( CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_IFileOpenDialog, (LPVOID *) &pfodSource );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfodSource->SetTitle( L"Secret Message" );
				if (FAILED(hr))
					_com_issue_error(hr);
				
				COMDLG_FILTERSPEC rgDialogFilters2[] = {
					{ L"Text Files (*.txt)", L"*.txt" },
					{ L"All Files", L"*.*" }
				};

				hr = pfodSource->SetFileTypes( CELEMS(rgDialogFilters2), rgDialogFilters2 );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfodSource->SetFileTypeIndex(2);
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfodSource->GetOptions( &dwOptions );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfodSource->SetOptions( dwOptions | FOS_FORCEFILESYSTEM );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfodSource->Show( GetConsoleWindow() );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfodSource->GetResult( &psiSecretMessage );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = psiSecretMessage->GetDisplayName( SIGDN_FILESYSPATH, &pwszFilePath );
				if (FAILED(hr))
					_com_issue_error(hr);

				IStreamPtr psMessageFile( NULL );
				hr = pfnSHCreateStreamOnFileEx( pwszFilePath, STGM_READ | STGM_SHARE_DENY_WRITE, FILE_ATTRIBUTE_NORMAL, FALSE, NULL, &psMessageFile );
				CoTaskMemFree( pwszFilePath );
				pwszFilePath = NULL;
				if (FAILED(hr))
					_com_issue_error(hr);
				
				STATSTG statMessageFileInfo = { 0 };
				hr = psMessageFile->Stat( &statMessageFileInfo, STATFLAG_NONAME );
				if (FAILED(hr))
					_com_issue_error(hr);

				DIMENSIONS_REQUIRED64 dr = { statMessageFileInfo.cbSize.QuadPart };
				
				wprintf( L"Image Width: %ld\n", pifCarrier->Width );
				wprintf( L"Image Height: %ld\n", pifCarrier->Height );
				printSize( L"Image Capacity: %.2f%s\n", RasterSteganography::GetImageCapacity64( pifCarrier, &dr ) );
				printSize( L"Message Length: %.2f%s\n", dr.cbMessageLength );

				if (dr.dwWidthRequired)
				{
					std::wstring question;
					question = L"The given message is too large to fit into the given image file. To encode the message into the image, it is neccessary to scale up the image to ";
					question += std::to_wstring( dr.dwWidthRequired ) + L" x " + std::to_wstring( dr.dwHeightRequired );
					question += L" pixels to accommodate the message. Do you wish to proceed?";
					int iSelectedButton = MessageBox( GetConsoleWindow(), question.c_str(), L"Steganography Issue", MB_OKCANCEL | MB_ICONQUESTION );
					if (!iSelectedButton)
						_com_issue_error(HRESULT_FROM_WIN32(GetLastError()));
					else if (iSelectedButton == IDCANCEL)
						_com_issue_error(HRESULT_FROM_WIN32(ERROR_CANCELLED));
					else if (iSelectedButton == IDOK)
					{
						wprintf( L"Scaling up the image to %llu x %llu pixels...\n", dr.dwWidthRequired, dr.dwHeightRequired );
						pifCarrier = ScaleImage( pifCarrier, &dr );
					}
				}

				wprintf( L"Encoding the message into the image...\n\n\n" );
				pifCarrier = Encode( pifCarrier, psMessageFile, ProgressSink );

				hr = CoCreateInstance( CLSID_FileSaveDialog, NULL, CLSCTX_INPROC_SERVER, IID_IFileSaveDialog, (PVOID *) &pfsdDestination );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->SetTitle( L"Output Image File" );
				if (FAILED(hr))
					_com_issue_error(hr);

				COMDLG_FILTERSPEC rgDialogFilters[] = {
					{ L"PNG Image Files (*.png)", L"*.png" },
					{ L"All Files", L"*.*" }
				};

				hr = pfsdDestination->SetFileTypes( CELEMS(rgDialogFilters), rgDialogFilters );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->SetFileTypeIndex(1);
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->GetOptions( &dwOptions );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->SetOptions( dwOptions | FOS_FORCEFILESYSTEM );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->SetSaveAsItem( psiImage );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->Show( GetConsoleWindow() );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->GetResult( &psiResult );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = psiResult->GetDisplayName( SIGDN_FILESYSPATH, &pwszFilePath );
				if (FAILED(hr))
					_com_issue_error(hr);

				pifCarrier->SaveFile( pwszFilePath );

				wprintf( L"Operation completed successfully!\n" );

				break;
			}
		case MY_OPTION_DECODE :
			{
				hr = pfodSource->GetResult( &psiImage );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = psiImage->GetDisplayName( SIGDN_FILESYSPATH, &pwszFilePath );
				if (FAILED(hr))
					_com_issue_error(hr);

				WIA::IImageFilePtr pifCarrier("WIA.ImageFile");

				pifCarrier->LoadFile( pwszFilePath );
				wprintf( L"Loaded image file '%s'...\n", pwszFilePath );

				CoTaskMemFree( pwszFilePath );
				pwszFilePath = NULL;

				hr = CoCreateInstance( CLSID_FileSaveDialog, NULL, CLSCTX_INPROC_SERVER, IID_IFileSaveDialog, (PVOID *) &pfsdDestination );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->SetTitle( L"Extract Message to..." );
				if (FAILED(hr))
					_com_issue_error(hr);

				COMDLG_FILTERSPEC rgDialogFilters[] = {
					{ L"Text Files (*.txt)", L"*.txt" },
					{ L"All Files", L"*.*" }
				};

				hr = pfsdDestination->SetFileTypes( CELEMS(rgDialogFilters), rgDialogFilters );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->SetFileTypeIndex(2);
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->GetOptions( &dwOptions );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->SetOptions( dwOptions | FOS_FORCEFILESYSTEM );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->SetFileName( L"Message" );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->Show( GetConsoleWindow() );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = pfsdDestination->GetResult( &psiResult );
				if (FAILED(hr))
					_com_issue_error(hr);

				hr = psiResult->GetDisplayName( SIGDN_FILESYSPATH, &pwszFilePath );
				if (FAILED(hr))
					_com_issue_error(hr);

				IStreamPtr psMessageFile( NULL );
				hr = pfnSHCreateStreamOnFileEx( pwszFilePath, STGM_WRITE | STGM_SHARE_DENY_WRITE | STGM_CREATE, FILE_ATTRIBUTE_NORMAL, FALSE, NULL, &psMessageFile );
				if (FAILED(hr))
					_com_issue_error(hr);

				wprintf( L"Decoding the message from the image...\n\n\n" );
				Decode( pifCarrier, psMessageFile, ProgressSink );

				wprintf( L"Operation completed successfully!\n" );

				break;
			}
		}
	}
	catch (_com_error &e)
	{
		SetConsoleTextAttribute( g_hScreenBuffer, FOREGROUND_RED );

		_tprintf(_T("Error:\n"));
		_tprintf(_T("Code = 0x%08lx\n"), e.Error());
		_tprintf(_T("Code meaning = %s\n"), e.ErrorMessage());
		_tprintf(_T("Source = %s\n"), (PCTSTR)(e.Source()));
		_tprintf(_T("Description = %s\n"), (PCTSTR)(e.Description()));

		SetConsoleTextAttribute( g_hScreenBuffer, REGULAR_TEXT_ATTR );
	}

	if (hShellLibrary)
		FreeLibrary(hShellLibrary);

	if (pwszFilePath)
		CoTaskMemFree(pwszFilePath);

	if (psiResult)
		psiResult->Release();

	if (psiSecretMessage)
		psiSecretMessage->Release();

	if (psiImage)
		psiImage->Release();

	if (pfdc)
		pfdc->Release();

	if (pfodSource)
		pfodSource->Release();

	if (pfsdDestination)
		pfsdDestination->Release();
	
	OleUninitialize();
	CloseHandle(g_hScreenBuffer);
	_getch();
	return 0;
}