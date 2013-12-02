//
//  TBOTRManager.h
//  TBOTRManager
//
//  Created by Thomas Balthazar on 30/09/13.
//  Copyright (c) 2013 Thomas Balthazar. All rights reserved.
//
//  This file is part of TBOTRManager.
//
//  TBOTRManager is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TBOTRManager is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public License
//  along with TBOTRManager.  If not, see <http://www.gnu.org/licenses/>.
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
- (void)reset;

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
- (void)disconnectRecipient:(NSString *)recipient
             forAccountName:(NSString *)accountName
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