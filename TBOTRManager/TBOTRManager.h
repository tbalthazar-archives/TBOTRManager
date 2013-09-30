//
//  TBOTRManager.h
//  TBOTRManager
//
//  Created by Thomas Balthazar on 30/09/13.
//  Copyright (c) 2013 Thomas Balthazar. All rights reserved.
//

#import <Foundation/Foundation.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
@interface TBOTRManager : NSObject

+ (TBOTRManager *)sharedOTRManager;

- (void)requestOTRSessionWithAccount:(NSString *)account;
- (void)encodeMessage:(NSString *)message
            recipient:(NSString *)recipient
          accountName:(NSString *)accountName
             protocol:(NSString *)protocol;

@end
