//
//  CSSMPubKeyDecrypt.h
//  PubKeyDecrypt
//
//  Created by Karsten Kusche on 18.04.14.
//  Copyright (c) 2014 briksoftware.com. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 \brief CSSMPubKeyDecrypt is a wrapper to the CSSM functions of the Security.framework.
 
 Usage: NSData* decryptedData = [CSSMPubKeyDecrypt decryptData: data usingPublicKey: key error: &error];
 */
@interface CSSMPubKeyDecrypt : NSObject

+ (NSData*)decryptData:(NSData*)data usingPublicKey:(SecKeyRef)key error:(NSError**)error;

@end
