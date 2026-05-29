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

#include "core.h"
#include <math.h>

#define CHANGE_ALPHA (1L << 24L)
#define CHANGE_RED (1L << 16L)
#define CHANGE_BLUE (1L << 8L)
#define CHANGE_GREEN (1L << 0L)

const LONG g_changeMasks[] = { CHANGE_RED, CHANGE_BLUE, CHANGE_GREEN };

template <typename IntegralT>
inline IntegralT devide_ceil(IntegralT x, IntegralT y)
{
	// return ceil(x / y);
	return x % y ? x / y + 1 : x / y;
}

STDMETHODIMP_(DWORD) RasterSteganography::GetImageCapacity(
		WIA::IImageFilePtr pCarrier,
		DIMENSIONS_REQUIRED *pDimRequired
		)
{
	DWORD width = pCarrier->Width;
	DWORD height = pCarrier->Height;
	DWORD capacity = width * height * CELEMS(g_changeMasks) / 8 - sizeof(LENGTH_PREFIX);
	
	if (pDimRequired)
	{
		pDimRequired->dwWidthRequired = pDimRequired->dwHeightRequired = 0;
		if (pDimRequired->cbMessageLength > capacity)
		{
			DWORD nPixelsRequired = devide_ceil((DWORD)((pDimRequired->cbMessageLength + sizeof(LENGTH_PREFIX)) * 8), (DWORD) CELEMS(g_changeMasks));
			double aspectRatio = sqrt((double) nPixelsRequired / (double) (width * height));
			pDimRequired->dwWidthRequired = (DWORD)(ceil((double) width * aspectRatio));
			pDimRequired->dwHeightRequired = (DWORD)(ceil((double) height * aspectRatio));
		}
	}

	return capacity;
}

STDMETHODIMP_(DWORD64) RasterSteganography::GetImageCapacity64(
		WIA::IImageFilePtr pCarrier,
		DIMENSIONS_REQUIRED64 *pDimRequired
		)
{
	DWORD64 width = pCarrier->Width;
	DWORD64 height = pCarrier->Height;
	DWORD64 capacity = width * height * CELEMS(g_changeMasks) / 8 - sizeof(LENGTH_PREFIX);
	
	if (pDimRequired)
	{
		pDimRequired->dwWidthRequired = pDimRequired->dwHeightRequired = 0;
		if (pDimRequired->cbMessageLength > capacity)
		{
			DWORD64 nPixelsRequired = devide_ceil((DWORD64)((pDimRequired->cbMessageLength + sizeof(LENGTH_PREFIX)) * 8), (DWORD64) CELEMS(g_changeMasks));
			double aspectRatio = sqrt((double) nPixelsRequired / (double) (width * height));
			pDimRequired->dwWidthRequired = (DWORD64)(ceil((double) width * aspectRatio));
			pDimRequired->dwHeightRequired = (DWORD64)(ceil((double) height * aspectRatio));
		}
	}

	return capacity;
}

inline WIA::IImageFilePtr ScaleImage(WIA::IImageFilePtr pCarrier, VARIANTARG *pvWidth, VARIANTARG *pvHeight)
{
	_variant_t v, v2;
	WIA::IImageProcessPtr pip("WIA.ImageProcess");
	
	pip->Filters->Add( pip->FilterInfos->GetItem(&(v = "Scale"))->FilterID, 0 );

	WIA::IPropertiesPtr pScaleProps( pip->Filters->Item[1L]->Properties );
	
	VariantChangeType(pvWidth, pvWidth, 0, VT_I4);
	pScaleProps->GetItem(&(v = "MaximumWidth"))->PutValue(pvWidth);

	VariantChangeType(pvHeight, pvHeight, 0, VT_I4);
	pScaleProps->GetItem(&(v = "MaximumHeight"))->PutValue(pvHeight);

	pScaleProps->GetItem(&(v = "PreserveAspectRatio"))->PutValue(&(v2 = false));

	return pip->Apply(pCarrier.GetInterfacePtr());
}

STDMETHODIMP_(WIA::IImageFilePtr) RasterSteganography::ScaleImage(WIA::IImageFilePtr pCarrier, DIMENSIONS_REQUIRED *pDimRequired)
{
	if (!pCarrier)
		_com_issue_error(E_INVALIDARG);

	if (!pDimRequired)
		_com_issue_error(E_INVALIDARG);

	VARIANT vWidth, vHeight;
	::VariantInit(&vWidth);
	vWidth.vt = VT_UI4;
	vWidth.ulVal = pDimRequired->dwWidthRequired;
	::VariantInit(&vHeight);
	vHeight.vt = VT_UI4;
	vHeight.ulVal = pDimRequired->dwHeightRequired;

	WIA::IImageFilePtr res = ::ScaleImage(pCarrier, &vWidth, &vHeight);

	::VariantClear(&vWidth);
	::VariantClear(&vHeight);

	return res;
}

STDMETHODIMP_(WIA::IImageFilePtr) RasterSteganography::ScaleImage(WIA::IImageFilePtr pCarrier, DIMENSIONS_REQUIRED64 *pDimRequired)
{
	if (!pCarrier)
		_com_issue_error(E_INVALIDARG);
	
	if (!pDimRequired)
		_com_issue_error(E_INVALIDARG);

	VARIANT vWidth, vHeight;
	::VariantInit(&vWidth);
	vWidth.vt = VT_UI8;
	vWidth.ullVal = pDimRequired->dwWidthRequired;
	::VariantInit(&vHeight);
	vHeight.vt = VT_UI8;
	vHeight.ullVal = pDimRequired->dwHeightRequired;

	WIA::IImageFilePtr res = ::ScaleImage(pCarrier, &vWidth, &vHeight);

	::VariantClear(&vWidth);
	::VariantClear(&vHeight);

	return res;
}

STDMETHODIMP_(WIA::IImageFilePtr) RasterSteganography::Encode(
		WIA::IImageFilePtr pCarrier,
		IStreamPtr pSecretMessage,
		PROGRESS_CALLBACK pProgress,
		LPVOID pvContext
		)
{
	if (!pCarrier)
		_com_issue_error(E_INVALIDARG);

	if (!pSecretMessage)
		_com_issue_error(E_INVALIDARG);
	
	HRESULT hr = S_OK;

	WIA::IVectorPtr pRaster( pCarrier->ARGBData );

	STATSTG ss = { 0 };
	hr = pSecretMessage->Stat( &ss, STATFLAG_NONAME );
	if (FAILED(hr))
		_com_issue_error(hr);

	LENGTH_PREFIX lp = (LENGTH_PREFIX)( ss.cbSize.QuadPart );
	LENGTH_PREFIX c = 0, f = 0;
	BYTE iBit = 7, data = 0;
	LONG nPixels = pRaster->Count;
	ULONG r = 1UL;

	VARIANT vPixel;
	VariantInit(&vPixel);
	vPixel.vt = VT_I4;
	LONG &pixel = vPixel.lVal;

	for (LONG iPixel = 1L; iPixel <= nPixels; iPixel++)
	{
		pixel = pRaster->GetItem(iPixel);

		for (BYTE j = 0; j < CELEMS(g_changeMasks); j++)
		{
			if (f != sizeof(lp) * 8)
			{
				if (lp & (1 << f))
					pixel |= g_changeMasks[j];
				else
					pixel &= ~(g_changeMasks[j]);
				
				f++;
				continue;
			}
			
			if (iBit++ == 7)
			{
				if (c++ == lp)
				{
					r = 0;
					break;
				}

				hr = pSecretMessage->Read( &data, 1UL, &r );
				if (FAILED(hr))
					_com_issue_error(hr);
				if (!r)
					_com_issue_error(STEGANO_E_UNEXPECTED_EOF);
				
				iBit = 0;
			}

			if (data & (1 << iBit))
				pixel |= g_changeMasks[j];
			else
				pixel &= ~(g_changeMasks[j]);
		}

		pRaster->PutItem(iPixel, &vPixel);

		if (pProgress && (f == sizeof(lp) * 8))
		{
			hr = pProgress( iPixel, nPixels, c, lp, pvContext );
			if (hr == S_FALSE)
			{
				VariantClear(&vPixel);
				return NULL;
			}

			if (FAILED(hr))
				_com_issue_error(hr);
		}

		if (!r)
			break;
	}

	if (r)
		_com_issue_error(STEGANO_E_INSUFFICIENT_CAPACITY);

	WIA::IImageProcessPtr pip("WIA.ImageProcess");
	
	_variant_t v;
	pip->Filters->Add( pip->FilterInfos->GetItem(&(v = "ARGB"))->FilterID, 0 );

	VARIANT &vRaster = vPixel;
	vRaster.vt = VT_DISPATCH;
	vRaster.pdispVal = pRaster.Detach();
	pip->Filters->Item[1L]->Properties->GetItem(&(v = "ARGBData"))->PutRefValue(&vRaster);
	VariantClear(&vRaster);

	pip->Filters->Add( pip->FilterInfos->GetItem(&(v = "Convert"))->FilterID, 0 );

	WIA::IPropertyPtr pFilterProp( pip->Filters->Item[2L]->Properties->GetItem(&(v = "FormatID")) );
	pFilterProp->PutValue(&(v = WIA::wiaFormatPNG));

	return pip->Apply(pCarrier.GetInterfacePtr());
}

void STDMETHODCALLTYPE RasterSteganography::Decode(
		WIA::IImageFilePtr pCarrier,
		IStreamPtr pSecretMessage,
		PROGRESS_CALLBACK pProgress,
		LPVOID pvContext
		)
{
	if (!pCarrier)
		_com_issue_error(E_INVALIDARG);

	if (!pSecretMessage)
		_com_issue_error(E_INVALIDARG);

	WIA::IVectorPtr pRaster( pCarrier->ARGBData );

	HRESULT hr = S_OK;
	LENGTH_PREFIX lp = 0, c = 0, f = 0;
	BYTE data = 0, iBit = 0;
	LONG nPixels = pRaster->Count;

	for (LONG iPixel = 1L; iPixel <= nPixels; iPixel++)
	{
		LONG pixel = pRaster->GetItem(iPixel);

		for (BYTE j = 0; j < CELEMS(g_changeMasks); j++)
		{
			if (f != sizeof(lp) * 8)
			{
				if (pixel & g_changeMasks[j])
					lp |= 1 << f;
				
				f++;
				continue;
			}
			
			if (pixel & g_changeMasks[j])
				data |= 1 << iBit;

			if (iBit++ == 7)
			{
				hr = pSecretMessage->Write( &data, 1UL, NULL );
				if (FAILED(hr))
					_com_issue_error(hr);

				if (++c == lp)
					return;
				
				data = iBit = 0;
			}
		}

		if (pProgress && (f == sizeof(lp) * 8))
		{
			hr = pProgress( iPixel, nPixels, c, lp, pvContext );
			if (hr == S_FALSE)
				return;

			if (FAILED(hr))
				_com_issue_error(hr);
		}
	}
}