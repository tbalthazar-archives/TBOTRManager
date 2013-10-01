//
//  TBOTRManager.h
//  TBOTRManager
//
//  Created by Thomas Balthazar on 30/09/13.
//  Copyright (c) 2013 Thomas Balthazar. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol TBOTRManagerDelegate;

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
@interface TBOTRManager : NSObject

@property (nonatomic, weak) id <TBOTRManagerDelegate> delegate;

+ (TBOTRManager *)sharedOTRManager;

+ (void)generatePrivateKeyForAccount:(NSString *)account protocol:(NSString *)protocol;
- (NSString *)OTRQueryMessageForAccount:(NSString *)account;
- (void)requestOTRSessionWithAccount:(NSString *)account;
- (NSString *)encodeMessage:(NSString *)message
                  recipient:(NSString *)recipient
                accountName:(NSString *)accountName
                   protocol:(NSString *)protocol;
- (NSString *)decodeMessage:(NSString *)message
                  recipient:(NSString *)recipient
                accountName:(NSString *)accountName
                   protocol:(NSString *)protocol;
- (NSString *)fingerprintForAccountName:(NSString *)accountName protocol:(NSString *)protocol;

@end

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
@protocol TBOTRManagerDelegate <NSObject>

- (void)OTRManager:(TBOTRManager *)OTRManager
       sendMessage:(NSString *)message
              from:(NSString *)sender
                to:(NSString *)recipient
          protocol:(NSString *)protocol;

@end


//2013-10-01 14:47:22.233 Cryptocat[1324:a0b] update_context_list_cb
//2013-10-01 14:47:22.234 Cryptocat[1324:a0b] create_instag_cb
//2013-10-01 14:47:22.237 Cryptocat[1324:a0b] policy_cb
//2013-10-01 14:47:22.274 Cryptocat[1324:a0b] max_message_size_cb
//2013-10-01 14:47:22.274 Cryptocat[1324:a0b] inject_message_cb
//2013-10-01 14:47:22.275 Cryptocat[1324:a0b] timer_control_cb


// [otrKit.delegate injectMessage:[NSString stringWithUTF8String:message] recipient:[NSString stringWithUTF8String:recipient] accountName:[NSString stringWithUTF8String:accountname] protocol:[NSString stringWithUTF8String:protocol]];