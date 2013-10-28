//
//  TBOTRManager.h
//  TBOTRManager
//
//  Created by Thomas Balthazar on 30/09/13.
//  Copyright (c) 2013 Thomas Balthazar. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol TBOTRManagerDelegate;

typedef void (^TBPrivateKeyCompletionBlock)();
typedef void (^TBMessageEncodingCompletionBlock)(NSString *encodedMessage);

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
@interface TBOTRManager : NSObject

@property (nonatomic, weak) id <TBOTRManagerDelegate> delegate;

+ (TBOTRManager *)sharedOTRManager;

- (NSString *)queryMessageForAccount:(NSString *)account;
- (void)generatePrivateKeyForAccount:(NSString *)account
                            protocol:(NSString *)protocol
                     completionBlock:(TBPrivateKeyCompletionBlock)completionBlock;
- (void)encodeMessage:(NSString *)message
            recipient:(NSString *)recipient
          accountName:(NSString *)accountName
             protocol:(NSString *)protocol
      completionBlock:(TBMessageEncodingCompletionBlock)completionBlock;
- (NSString *)decodeMessage:(NSString *)message
                     sender:(NSString *)sender
                accountName:(NSString *)accountName
                   protocol:(NSString *)protocol;
- (NSString *)fingerprintForAccountName:(NSString *)accountName protocol:(NSString *)protocol;
- (NSString *)fingerprintForRecipient:(NSString *)recipient
                          accountName:(NSString *)accountName
                             protocol:(NSString *)protocol;
- (BOOL)isConversationEncryptedForAccountName:(NSString *)accountName
                                    recipient:(NSString *)recipient
                                     protocol:(NSString *)protocol;

@end

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
@protocol TBOTRManagerDelegate <NSObject>

- (void)OTRManager:(TBOTRManager *)OTRManager
       sendMessage:(NSString *)message
       accountName:(NSString *)accountName
                to:(NSString *)recipient
          protocol:(NSString *)protocol;
- (void)OTRManager:(TBOTRManager *)OTRManager
didUpdateEncryptionStatus:(BOOL)isEncrypted
      forRecipient:(NSString *)recipient
       accountName:(NSString *)accountName
          protocol:(NSString *)protocol;

@end