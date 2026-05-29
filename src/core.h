#ifndef HDR_RASTER_STEGANOGRAPHY
#define HDR_RASTER_STEGANOGRAPHY

#include <Windows.h>
#import "progid:WIA.ImageFile"

#define CELEMS(arr) ( sizeof(arr) / sizeof(arr[0]) )

namespace RasterSteganography
{
	struct DIMENSIONS_REQUIRED
	{
		DWORD cbMessageLength;
		DWORD dwWidthRequired;
		DWORD dwHeightRequired;
	};

	struct DIMENSIONS_REQUIRED64
	{
		DWORD64 cbMessageLength;
		DWORD64 dwWidthRequired;
		DWORD64 dwHeightRequired;
	};

	// You can modify the following line if you wish to change
	// the type of length prefix used to determine the amount
	// of data that is concealed within the image. Depending on
	// how large the LP type is, setting this type affects the
	// maximum length of messages that can be encoded into an
	// image. For example, a 32-bit length prefix allows for
	// encoding messages up to 4-GB in size, whereas a 16-bit
	// one allows for encoding up to 64-KB messages.
	// The LP type must be set to an unsigned integral type,
	// typically WORD, DWORD, or ULONGLONG.
	typedef DWORD LENGTH_PREFIX;

	typedef HRESULT (CALLBACK *PROGRESS_CALLBACK)(LONG lPixelOffset, LONG lPixelCount, LENGTH_PREFIX cbDataOffset, LENGTH_PREFIX cbDataLength, LPVOID pvContext);

	WIA::IImageFilePtr STDMETHODCALLTYPE Encode(
		WIA::IImageFilePtr pCarrier,
		IStreamPtr pSecretMessage,
		PROGRESS_CALLBACK pProgress = NULL,
		LPVOID pvContext = NULL
		);
	
	void STDMETHODCALLTYPE Decode(
		WIA::IImageFilePtr pCarrier,
		IStreamPtr pSecretMessage,
		PROGRESS_CALLBACK pProgress = NULL,
		LPVOID pvContext = NULL
		);

	DWORD STDMETHODCALLTYPE GetImageCapacity(
		WIA::IImageFilePtr pCarrier,
		DIMENSIONS_REQUIRED *pDimRequired
		);

	DWORD64 STDMETHODCALLTYPE GetImageCapacity64(
		WIA::IImageFilePtr pCarrier,
		DIMENSIONS_REQUIRED64 *pDimRequired
		);

	WIA::IImageFilePtr STDMETHODCALLTYPE ScaleImage(
		WIA::IImageFilePtr pCarrier,
		DIMENSIONS_REQUIRED *pDimRequired
		);

	WIA::IImageFilePtr STDMETHODCALLTYPE ScaleImage(
		WIA::IImageFilePtr pCarrier,
		DIMENSIONS_REQUIRED64 *pDimRequired
		);
};

#define CUSTOM_ERROR_CODE(code) MAKE_HRESULT( SEVERITY_ERROR, FACILITY_ITF, 0x0200 + (code) )

#define STEGANO_E_INSUFFICIENT_CAPACITY CUSTOM_ERROR_CODE(1)
#define STEGANO_E_UNEXPECTED_EOF CUSTOM_ERROR_CODE(2)

#endif