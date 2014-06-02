CSSMPublicKeyDecrypt
====================

Implementation of Public-Key Decrypt using CSSM in Security.framework

Usage
=====

	NSData* pemData = [NSData dataWithContentsOfFile:@"keyFile.pem"];
	SecExternalFormat format = kSecFormatOpenSSL;
	SecExternalItemType itemType = kSecItemTypePrivateKey;
	SecKeyImportExportFlags importExportFlags = 0;
	SecItemImportExportKeyParameters parameters = {};
	NSArray* items = @[];
	
	OSStatus importWorked = SecItemImport((CFDataRef)pemData, NULL, &format, &itemType, importExportFlags, &parameters, NULL, (CFArrayRef*)&items);
	if (importWorked == noErr)
	{
		for (id idKey in items)
		{
			SecKeyRef key = (SecKeyRef)idKey;
			NSError* error = nil;
			
			NSData* decryptedData = [CSSMPubKeyDecrypt decryptData:encryptedData usingPublicKey:key error:&error];
			if (!decryptedData)
			{
				NSLog(@"error decrypting data: %@", error);
			}
		}
		CFRelease((CFArrayRef)items);
	}

