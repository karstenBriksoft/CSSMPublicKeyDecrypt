//
//  CSSMPubKeyDecrypt.m
//  PubKeyDecrypt
//
//  Created by Karsten Kusche on 18.04.14.
//  Copyright (c) 2014 briksoftware.com. All rights reserved.
//

#import "CSSMPubKeyDecrypt.h"

// CSSM is deprecated but has to be used if the functionality is missing in Security.framework (says the documentation)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

@implementation CSSMPubKeyDecrypt

+ (NSData*)decryptData:(NSData*)data usingPublicKey:(SecKeyRef)key error:(NSError**)error
{
	CSSMPubKeyDecrypt* decrypter = [[self alloc] init];
	NSData* resultData = [decrypter decryptData:data usingPublicKey:key error:error];
	[decrypter release];
	return resultData;
}

- (CSSM_RETURN)cryptHandleForCsp:(CSSM_CSP_HANDLE) cspHandle
							 key:(const CSSM_KEY*) key
							into:(CSSM_CC_HANDLE*) ccHandle
{
    CSSM_RETURN         cssmReturn;
    CSSM_CC_HANDLE      ccHand = 0;
    CSSM_ACCESS_CREDENTIALS credentials;
    
   
    memset(&credentials, 0, sizeof(CSSM_ACCESS_CREDENTIALS));
	cssmReturn = CSSM_CSP_CreateAsymmetricContext(cspHandle,
											key->KeyHeader.AlgorithmId,
											&credentials,         // access
											key,
											CSSM_PADDING_PKCS1,
											&ccHand);
	
    if(cssmReturn) {
        return cssmReturn;
    }
    *ccHandle = ccHand;
    return CSSM_OK;
}


- (CSSM_RETURN) decryptData:(const CSSM_DATA*) encryptedData
					 forCsp:(CSSM_CSP_HANDLE)  cspHandle
						key:(const CSSM_KEY*)  key
					   into:(CSSM_DATA*)       outData
{
    CSSM_RETURN     cssmReturn;
    CSSM_CC_HANDLE  ccHandle;
    CSSM_DATA       remData = {0, NULL};
    CSSM_SIZE       bytesDecrypted;
    
    cssmReturn = [self cryptHandleForCsp:cspHandle key:key into:&ccHandle];
	if (cssmReturn)
	{
        return cssmReturn;
    }
    
	CSSM_CONTEXT_ATTRIBUTE attribute = {};
	attribute.AttributeType = CSSM_ATTRIBUTE_MODE;
	attribute.AttributeLength = sizeof(UInt32);
	attribute.Attribute.Uint32 = CSSM_ALGMODE_PUBLIC_KEY;
	
	cssmReturn = CSSM_UpdateContextAttributes(ccHandle, 1, &attribute);
    if (cssmReturn)
	{
		return cssmReturn;
	}
	
	outData->Length = 0;
    outData->Data = NULL;
    cssmReturn = CSSM_DecryptData(ccHandle,
							encryptedData,
							1,
							outData,
							1,
							&bytesDecrypted,
							&remData);
    CSSM_DeleteContext(ccHandle);
    
	if(cssmReturn)
	{
        return cssmReturn;
    }
    
    outData->Length = bytesDecrypted;
 
	if(remData.Length != 0) {
        /* append remaining data to plainText */
        CSSM_SIZE newLen = outData->Length + remData.Length;

        outData->Data = (uint8 *)realloc(outData->Data,newLen);
		
        memmove(outData->Data + outData->Length,
				remData.Data, remData.Length);
        outData->Length = newLen;
        free(remData.Data);
    }
    return CSSM_OK;
}

- (NSData*)decryptData:(NSData*)data usingPublicKey:(SecKeyRef)key error:(NSError**)errorPtr
{
	const CSSM_KEY* cssm_key = nil;
	CSSM_CSP_HANDLE cspHandle;
	SecKeyGetCSSMKey(key, &cssm_key);
	SecKeyGetCSPHandle(key, &cspHandle);
	CSSM_DATA inData = {};
	inData.Data = (uint8_t*)[data bytes];
	inData.Length = [data length];
	CSSM_DATA outData = {};
	CSSM_RETURN returnValue = [self decryptData:&inData forCsp:cspHandle key:cssm_key into:&outData];
	if (returnValue)
	{
		extern char* cssmErrorString(CSSM_RETURN errCode);
		NSError* error = [NSError errorWithDomain:[NSString stringWithUTF8String:cssmErrorString(returnValue)]
											 code:returnValue
										 userInfo:nil];
		if (errorPtr)
		{
			*errorPtr = error;
		}
		else
		{
			NSLog(@"Error in %@: %@",self,error);
		}
		return nil;
	}
	return [NSData dataWithBytesNoCopy:outData.Data length:outData.Length freeWhenDone:YES];
}
@end

#pragma clang diagnostic pop
