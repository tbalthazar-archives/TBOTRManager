//
//  TBOTRManager.m
//  TBOTRManager
//
//  Created by Thomas Balthazar on 30/09/13.
//  Copyright (c) 2013 Thomas Balthazar. All rights reserved.
//
//  This file is part of TBOTRManager.
//
//  TBOTRManager is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TBOTRManager is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TBOTRManager.  If not, see <http://www.gnu.org/licenses/>.
//

#import "TBOTRManager.h"

#import "proto.h"
#import "context.h"
#import "message.h"
#import "privkey.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
@interface TBOTRManager ()

@property (nonatomic, strong) NSMutableArray *pkCompletionBlocks;
@property (nonatomic, retain) NSTimer *pollTimer;
@property (nonatomic, strong) dispatch_queue_t bgQueue;
@property (nonatomic, assign) BOOL isGeneratingPrivateKey;

/*
 * The Authenticated Key Exchange (AKE) sequence consists of 4 messages :
 *  - D-H Commit Message (?OTR:AAMC)
 *  - D-H Key Message (?OTR:AAMK)
 *  - Reveal Signature Message (?OTR:AAMR)
 *  - Signature Message (?OTR:AAMS)
 *
 * (see the protocol spec here and search for the "D-H Commit Message" title : 
 *  https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html )
 *
 * The gone_secure callback is called after you receive the AAMR message.
 * When gone_secure is called, you know that the next message libotr will
 * ask you to send (via the inject_message callback) is the AAMS message.
 * After this message has been sent, you can consider the conversation to be
 * secured and start sending the user messages (Data Message, ?OTR:AAMD), the
 * conversation between both ends can start.
 *
 */
@property (nonatomic, assign) BOOL nextMessageIsSignatureMessage;

+ (NSString *)documentsDirectory;
+ (NSString *)privateKeyPath;
+ (NSString *)instanceTagPath;
- (ConnContext *)contextForUsername:(NSString *)username
                        accountName:(NSString *)accountName
                           protocol:(NSString *) protocol;
- (void)messagePoll;
- (void)updateEncryptionStatusWithContext:(ConnContext*)context;

@end

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
@implementation TBOTRManager

static TBOTRManager *sharedOTRManager = nil;
static OtrlUserState otr_userstate = NULL;
static void *newkeyp;

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
#pragma mark OtrlMessageAppOps

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Return the OTR policy for the given context.
 */
static OtrlPolicy policy_cb(void *opdata, ConnContext *context) {
  NSLog(@"policy_cb");
  return OTRL_POLICY_DEFAULT;
  //return OTRL_POLICY_REQUIRE_ENCRYPTION;
  //return OTRL_POLICY_ALLOW_V3;
  //return OTRL_POLICY_ALWAYS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Generate a private key for the given accountname/protocol
 */
static void create_privkey_cb(void *opdata, const char *accountname, const char *protocol) {
  NSLog(@"create_privkey_cb");
  NSString *privateKeyPath = [TBOTRManager privateKeyPath];
  const char *privateKeyPathC = [privateKeyPath cStringUsingEncoding:NSUTF8StringEncoding];
  
  otrl_privkey_generate(otr_userstate, privateKeyPathC, accountname, protocol);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Report whether you think the given user is online.  Return 1 if
 * you think he is, 0 if you think he isn't, -1 if you're not sure.
 *
 * If you return 1, messages such as heartbeats or other
 * notifications may be sent to the user, which could result in "not
 * logged in" errors if you're wrong.
 */
// TODO: implement this function
static int is_logged_in_cb(void *opdata, const char *accountname,
                           const char *protocol, const char *recipient) {
  NSLog(@"is_logged_in_cb");
	return 1;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Send the given IM to the given recipient from the given
 * accountname/protocol.
 */
static void inject_message_cb(void *opdata, const char *accountname,
                              const char *protocol, const char *recipient, const char *message) {
  NSLog(@"inject_message_cb");
  TBOTRManager *otrManager = [TBOTRManager sharedOTRManager];
  NSString *accountNameString = [NSString stringWithUTF8String:accountname];
  NSString *protocolString = [NSString stringWithUTF8String:protocol];
  NSString *recipientString = [NSString stringWithUTF8String:recipient];
  
  // asks the delegate to send the message
  if ([otrManager.delegate
       respondsToSelector:@selector(OTRManager:sendMessage:accountName:to:protocol:)]) {
    [otrManager.delegate OTRManager:otrManager
                        sendMessage:[NSString stringWithUTF8String:message]
                        accountName:accountNameString
                                 to:recipientString
                           protocol:protocolString];
  }

  // if the message we just asked to send was the signature message, notify the delegate
  // that the conversation can be considered as secure
  if (otrManager.nextMessageIsSignatureMessage) {
    ConnContext *context = [otrManager contextForUsername:recipientString
                                              accountName:accountNameString
                                                 protocol:protocolString];
    [otrManager updateEncryptionStatusWithContext:context];
    otrManager.nextMessageIsSignatureMessage = NO;
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/* Display a notification message for a particular accountname /
 * protocol / username conversation.
 */
// TODO: implement this function
static void update_context_list_cb(void *opdata) {
  NSLog(@"update_context_list_cb");
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * A new fingerprint for the given user has been received.
 */
static void confirm_fingerprint_received_cb(void *opdata, OtrlUserState us,
                                            const char *accountname, const char *protocol,
                                            const char *username, unsigned char fingerprint[20]) {
  NSLog(@"confirm_fingerprint_received_cb for username : %s, accountname : %s",
        username, accountname);
  char our_hash[45], their_hash[45];
  
  // TODO: check if I cannot find the context using the obj-c method i wrote
  ConnContext *context = otrl_context_find(otr_userstate, username, accountname, protocol,
                                           OTRL_INSTAG_BEST, NO, NULL, NULL, NULL);
  if (!context) return;
  
  otrl_privkey_fingerprint(otr_userstate, our_hash, context->accountname, context->protocol);
  otrl_privkey_hash_to_human(their_hash, fingerprint);
  
  // TODO: implement this function
  /*
   OTRKit *otrKit = [OTRKit sharedInstance];
   if (otrKit.delegate && [otrKit.delegate respondsToSelector:@selector(showFingerprintConfirmationForAccountName:protocol:userName:theirHash:ourHash:)]) {
   [otrKit.delegate showFingerprintConfirmationForAccountName:[NSString stringWithUTF8String:accountname] protocol:[NSString stringWithUTF8String:protocol] userName:[NSString stringWithUTF8String:username] theirHash:[NSString stringWithUTF8String:their_hash] ourHash:[NSString stringWithUTF8String:our_hash]];
   }
   */
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * The list of known fingerprints has changed.  Write them to disk.
 */
// TODO: implement this function
static void write_fingerprints_cb(void *opdata) {
  NSLog(@"write_fingerprints_cb");
  /*
   OTRKit *otrKit = [OTRKit sharedInstance];
   if (otrKit.delegate && [otrKit.delegate respondsToSelector:@selector(writeFingerprints)]) {
   [otrKit.delegate writeFingerprints];
   } else {
   FILE *storef;
   NSString *path = [otrKit fingerprintsPath];
   storef = fopen([path UTF8String], "wb");
   if (!storef) return;
   otrl_privkey_write_fingerprints_FILEp(userState, storef);
   fclose(storef);
   }
   */
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * A ConnContext has entered a secure state.
 */
static void gone_secure_cb(void *opdata, ConnContext *context) {
  NSLog(@"gone_secure_cb");
  /*
   * The conversation is secured from our side. The next message that will be sent 
   * (via inject_message) is the signature message.
   */
  TBOTRManager *OTRManager = [TBOTRManager sharedOTRManager];
  OTRManager.nextMessageIsSignatureMessage = YES;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * A ConnContext has left a secure state.
 */
static void gone_insecure_cb(void *opdata, ConnContext *context) {
  NSLog(@"gone_insecure_cb");
  TBOTRManager *OTRManager = [TBOTRManager sharedOTRManager];
  [OTRManager updateEncryptionStatusWithContext:context];
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * We have completed an authentication, using the D-H keys we
 * already knew.  is_reply indicates whether we initiated the AKE.
 */
static void still_secure_cb(void *opdata, ConnContext *context, int is_reply) {
  NSLog(@"still_secure_cb");
  TBOTRManager *OTRManager = [TBOTRManager sharedOTRManager];
  [OTRManager updateEncryptionStatusWithContext:context];
}

/*
 * Find the maximum message size supported by this protocol.
 *
 * This method is called whenever a message is about to be sent with
 * fragmentation enabled.  The return value is checked against the size of
 * the message to be sent to determine whether fragmentation is necessary.
 *
 * Setting max_message_size to NULL will disable the fragmentation of all
 * sent messages; returning 0 from this callback will disable fragmentation
 * of a particular message.  The latter is useful, for example, for
 * protocols like XMPP (Jabber) that do not require fragmentation at all.
 */
static int max_message_size_cb(void *opdata, ConnContext *context) {
  NSLog(@"max_message_size_cb");
  return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Return a newly allocated string containing a human-friendly
 * representation for the given account
 */
// TODO: implement this function
static const char *account_display_name_cb(void *opdata, const char *accountname,
                                           const char *protocol) {
  NSLog(@"account_display_name_cb");
  //  const char *ret = strdup([[accountFromAccountID(accountname) formattedUID] UTF8String]);
  //  return ret;
  return "foo";
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Deallocate a string returned by account_name
 */
// TODO: implement this function
static void account_display_name_free_cb(void *opdata, const char *account_display_name) {
  NSLog(@"account_display_name_free_cb");
	if (account_display_name)
		free((char *)account_display_name);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * We received a request from the buddy to use the current "extra"
 * symmetric key.  The key will be passed in symkey, of length
 * OTRL_EXTRAKEY_BYTES.  The requested use, as well as use-specific
 * data will be passed so that the applications can communicate other
 * information (some id for the data transfer, for example).
 */
// TODO: implement this function
static void received_symkey_cb(void *opdata, ConnContext *context,
                               unsigned int use, const unsigned char *usedata,
                               size_t usedatalen, const unsigned char *symkey) {
  NSLog(@"received_symkey_cb");
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/* Return a string according to the error event. This string will then
 * be concatenated to an OTR header to produce an OTR protocol error
 * message. The following are the possible error events:
 * - OTRL_ERRCODE_ENCRYPTION_ERROR
 * 		occured while encrypting a message
 * - OTRL_ERRCODE_MSG_NOT_IN_PRIVATE
 * 		sent encrypted message to somebody who is not in
 * 		a mutual OTR session
 * - OTRL_ERRCODE_MSG_UNREADABLE
 *		sent an unreadable encrypted message
 * - OTRL_ERRCODE_MSG_MALFORMED
 * 		message sent is malformed */
static const char* otr_error_message_cb(void *opdata, ConnContext *context,
                                        OtrlErrorCode err_code) {
  NSLog(@"otr_error_message_cb");
  NSString *errorString = nil;
  switch (err_code)
  {
    case OTRL_ERRCODE_NONE :
      break;
    case OTRL_ERRCODE_ENCRYPTION_ERROR :
      errorString = @"Error occurred encrypting message.";
      break;
    case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE :
      if (context) {
        errorString = [NSString stringWithFormat:
                       @"You sent encrypted data to %s, who wasn't expecting it.",
                       context->accountname];
      }
      break;
    case OTRL_ERRCODE_MSG_UNREADABLE :
      errorString = @"You transmitted an unreadable encrypted message.";
      break;
    case OTRL_ERRCODE_MSG_MALFORMED :
      errorString = @"You transmitted a malformed data message.";
      break;
  }
  return [errorString UTF8String];
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Deallocate a string returned by otr_error_message
 */
// TODO: implement this function
static void otr_error_message_free_cb(void *opdata, const char *err_msg) {
  NSLog(@"otr_error_message_free_cb");
  // Leak memory here instead of crashing:
  // if (err_msg) free((char*)err_msg);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Return a string that will be prefixed to any resent message. If this
 * function is not provided by the application then the default prefix,
 * "[resent]", will be used.
 */
// TODO: implement this function
static const char *resent_msg_prefix_cb(void *opdata, ConnContext *context) {
  NSLog(@"resent_msg_prefix_cb");
  NSString *resentString = @"[resent]";
	return [resentString UTF8String];
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Deallocate a string returned by resent_msg_prefix
 */
// TODO: implement this function
static void resent_msg_prefix_free_cb(void *opdata, const char *prefix) {
  NSLog(@"resent_msg_prefix_free_cb");
  // Leak memory here instead of crashing:
	// if (prefix) free((char*)prefix);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Update the authentication UI with respect to SMP events
 * These are the possible events:
 * - OTRL_SMPEVENT_ASK_FOR_SECRET
 *      prompt the user to enter a shared secret. The sender application
 *      should call otrl_message_initiate_smp, passing NULL as the question.
 *      When the receiver application resumes the SM protocol by calling
 *      otrl_message_respond_smp with the secret answer.
 * - OTRL_SMPEVENT_ASK_FOR_ANSWER
 *      (same as OTRL_SMPEVENT_ASK_FOR_SECRET but sender calls
 *      otrl_message_initiate_smp_q instead)
 * - OTRL_SMPEVENT_CHEATED
 *      abort the current auth and update the auth progress dialog
 *      with progress_percent. otrl_message_abort_smp should be called to
 *      stop the SM protocol.
 * - OTRL_SMPEVENT_INPROGRESS 	and
 *   OTRL_SMPEVENT_SUCCESS 		and
 *   OTRL_SMPEVENT_FAILURE    	and
 *   OTRL_SMPEVENT_ABORT
 *      update the auth progress dialog with progress_percent
 * - OTRL_SMPEVENT_ERROR
 *      (same as OTRL_SMPEVENT_CHEATED)
 */
// TODO: implement this function
static void handle_smp_event_cb(void *opdata, OtrlSMPEvent smp_event,
                                ConnContext *context, unsigned short progress_percent,
                                char *question) {
  NSLog(@"handle_smp_event_cb");
  /*
   if (!context) return;
   switch (smp_event)
   {
   case OTRL_SMPEVENT_NONE :
   break;
   case OTRL_SMPEVENT_ASK_FOR_SECRET :
   otrg_dialog_socialist_millionaires(context);
   break;
   case OTRL_SMPEVENT_ASK_FOR_ANSWER :
   otrg_dialog_socialist_millionaires_q(context, question);
   break;
   case OTRL_SMPEVENT_CHEATED :
   otrg_plugin_abort_smp(context);
   // FALLTHROUGH
   case OTRL_SMPEVENT_IN_PROGRESS :
   case OTRL_SMPEVENT_SUCCESS :
   case OTRL_SMPEVENT_FAILURE :
   case OTRL_SMPEVENT_ABORT :
   otrg_dialog_update_smp(context,
   smp_event, ((gdouble)progress_percent)/100.0);
   break;
   case OTRL_SMPEVENT_ERROR :
   otrg_plugin_abort_smp(context);
   break;
   }
   */
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/* Handle and send the appropriate message(s) to the sender/recipient
 * depending on the message events. All the events only require an opdata,
 * the event, and the context. The message and err will be NULL except for
 * some events (see below). The possible events are:
 * - OTRL_MSGEVENT_ENCRYPTION_REQUIRED
 *      Our policy requires encryption but we are trying to send
 *      an unencrypted message out.
 * - OTRL_MSGEVENT_ENCRYPTION_ERROR
 *      An error occured while encrypting a message and the message
 *      was not sent.
 * - OTRL_MSGEVENT_CONNECTION_ENDED
 *      Message has not been sent because our buddy has ended the
 *      private conversation. We should either close the connection,
 *      or refresh it.
 * - OTRL_MSGEVENT_SETUP_ERROR
 *      A private conversation could not be set up. A gcry_error_t
 *      will be passed.
 * - OTRL_MSGEVENT_MSG_REFLECTED
 *      Received our own OTR messages.
 * - OTRL_MSGEVENT_MSG_RESENT
 *      The previous message was resent.
 * - OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE
 *      Received an encrypted message but cannot read
 *      it because no private connection is established yet.
 * - OTRL_MSGEVENT_RCVDMSG_UNREADABLE
 *      Cannot read the received message.
 * - OTRL_MSGEVENT_RCVDMSG_MALFORMED
 *      The message received contains malformed data.
 * - OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD
 *      Received a heartbeat.
 * - OTRL_MSGEVENT_LOG_HEARTBEAT_SENT
 *      Sent a heartbeat.
 * - OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR
 *      Received a general OTR error. The argument 'message' will
 *      also be passed and it will contain the OTR error message.
 * - OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED
 *      Received an unencrypted message. The argument 'smessage' will
 *      also be passed and it will contain the plaintext message.
 * - OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED
 *      Cannot recognize the type of OTR message received.
 * - OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE
 *      Received and discarded a message intended for another instance.
 */
// TODO: implement this function
static void handle_msg_event_cb(void *opdata, OtrlMessageEvent msg_event,
                                ConnContext *context, const char* message, gcry_error_t err) {
  NSLog(@"handle_msg_event_cb");
  /*
   PurpleConversation *conv = NULL;
   gchar *buf;
   OtrlMessageEvent * last_msg_event;
   
   if (!context) return;
   
   conv = otrg_plugin_context_to_conv(context, 1);
   last_msg_event = g_hash_table_lookup(conv->data, "otr-last_msg_event");
   
   switch (msg_event)
   {
   case OTRL_MSGEVENT_NONE:
   break;
   case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
   buf = g_strdup_printf(_("You attempted to send an "
   "unencrypted message to %s"), context->username);
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, _("Attempting to"
   " start a private conversation..."), 1, OTRL_NOTIFY_WARNING,
   _("OTR Policy Violation"), buf,
   _("Unencrypted messages to this recipient are "
   "not allowed.  Attempting to start a private "
   "conversation.\n\nYour message will be "
   "retransmitted when the private conversation "
   "starts."));
   g_free(buf);
   break;
   case OTRL_MSGEVENT_ENCRYPTION_ERROR:
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, _("An error occurred "
   "when encrypting your message.  The message was not sent."),
   1, OTRL_NOTIFY_ERROR, _("Error encrypting message"),
   _("An error occurred when encrypting your message"),
   _("The message was not sent."));
   break;
   case OTRL_MSGEVENT_CONNECTION_ENDED:
   buf = g_strdup_printf(_("%s has already closed his/her private "
   "connection to you"), context->username);
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, _("Your message "
   "was not sent.  Either end your private conversation, "
   "or restart it."), 1, OTRL_NOTIFY_ERROR,
   _("Private connection closed"), buf,
   _("Your message was not sent.  Either close your "
   "private connection to him, or refresh it."));
   g_free(buf);
   break;
   case OTRL_MSGEVENT_SETUP_ERROR:
   if (!err) {
   err = GPG_ERR_INV_VALUE;
   }
   switch(gcry_err_code(err)) {
   case GPG_ERR_INV_VALUE:
   buf = g_strdup(_("Error setting up private "
   "conversation: Malformed message received"));
   break;
   default:
   buf = g_strdup_printf(_("Error setting up private "
   "conversation: %s"), gcry_strerror(err));
   break;
   }
   
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, buf, 1,
   OTRL_NOTIFY_ERROR, _("OTR Error"), buf, NULL);
   g_free(buf);
   break;
   case OTRL_MSGEVENT_MSG_REFLECTED:
   display_otr_message_or_notify(opdata,
   context->accountname, context->protocol,
   context->username,
   _("We are receiving our own OTR messages.  "
   "You are either trying to talk to yourself, "
   "or someone is reflecting your messages back "
   "at you."), 1, OTRL_NOTIFY_ERROR,
   _("OTR Error"), _("We are receiving our own OTR messages."),
   _("You are either trying to talk to yourself, "
   "or someone is reflecting your messages back "
   "at you."));
   break;
   case OTRL_MSGEVENT_MSG_RESENT:
   buf = g_strdup_printf(_("<b>The last message to %s was resent."
   "</b>"), context->username);
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, buf, 1,
   OTRL_NOTIFY_INFO, _("Message resent"), buf, NULL);
   g_free(buf);
   break;
   case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
   buf = g_strdup_printf(_("<b>The encrypted message received from "
   "%s is unreadable, as you are not currently communicating "
   "privately.</b>"), context->username);
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, buf, 1,
   OTRL_NOTIFY_INFO, _("Unreadable message"), buf, NULL);
   g_free(buf);
   break;
   case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
   buf = g_strdup_printf(_("We received an unreadable "
   "encrypted message from %s."), context->username);
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, buf, 1,
   OTRL_NOTIFY_ERROR, _("OTR Error"), buf, NULL);
   g_free(buf);
   break;
   case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
   buf = g_strdup_printf(_("We received a malformed data "
   "message from %s."), context->username);
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, buf, 1,
   OTRL_NOTIFY_ERROR, _("OTR Error"), buf, NULL);
   g_free(buf);
   break;
   case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
   buf = g_strdup_printf(_("Heartbeat received from %s.\n"),
   context->username);
   log_message(opdata, buf);
   g_free(buf);
   break;
   case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
   buf = g_strdup_printf(_("Heartbeat sent to %s.\n"),
   context->username);
   log_message(opdata, buf);
   g_free(buf);
   break;
   case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, message, 1,
   OTRL_NOTIFY_ERROR, _("OTR Error"), message, NULL);
   break;
   case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
   buf = g_strdup_printf(_("<b>The following message received "
   "from %s was <i>not</i> encrypted: [</b>%s<b>]</b>"),
   context->username, message);
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, buf, 1,
   OTRL_NOTIFY_INFO, _("Received unencrypted message"),
   buf, NULL);
   emit_msg_received(context, buf);
   g_free(buf);
   break;
   case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
   buf = g_strdup_printf(_("Unrecognized OTR message received "
   "from %s.\n"), context->username);
   log_message(opdata, buf);
   g_free(buf);
   break;
   case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
   if (*last_msg_event == msg_event) {
   break;
   }
   buf = g_strdup_printf(_("%s has sent a message intended for a "
   "different session. If you are logged in multiple times, "
   "another session may have received the message."),
   context->username);
   display_otr_message_or_notify(opdata, context->accountname,
   context->protocol, context->username, buf, 1,
   OTRL_NOTIFY_INFO, _("Received message for a different "
   "session"), buf, NULL);
   g_free(buf);
   break;
   }
   
   *last_msg_event = msg_event;
   */
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Create a instance tag for the given accountname/protocol if
 * desired.
 */
static void create_instag_cb(void *opdata, const char *accountname, const char *protocol) {
  FILE *instagf;
  NSString *isntanceTagPath = [TBOTRManager instanceTagPath];
  instagf = fopen([isntanceTagPath UTF8String], "w+b");
  otrl_instag_generate_FILEp(otr_userstate, instagf, accountname, protocol);
  fclose(instagf);
  
  NSLog(@"create_instag_cb for %@, %@",
        [NSString stringWithUTF8String:accountname], [NSString stringWithUTF8String:protocol]);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Called immediately before a data message is encrypted, and after a data
 * message is decrypted. The OtrlConvertType parameter has the value
 * OTRL_CONVERT_SENDING or OTRL_CONVERT_RECEIVING to differentiate these
 * cases.
 */
// TODO: implement this function
static void convert_data_cb(void *opdata, ConnContext *context,
                            OtrlConvertType convert_type, char ** dest, const char *src) {
  NSLog(@"convert_data_cb");
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Deallocate a string returned by convert_msg.
 */
// TODO: implement this function
static void convert_data_free_cb(void *opdata, ConnContext *context, char *dest) {
  NSLog(@"convert_data_free_cb");
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/* When timer_control is called, turn off any existing periodic
 * timer.
 *
 * Additionally, if interval > 0, set a new periodic timer
 * to go off every interval seconds.  When that timer fires, you
 * must call otrl_message_poll(userstate, uiops, uiopdata); from the
 * main libotr thread.
 *
 * The timing does not have to be exact; this timer is used to
 * provide forward secrecy by cleaning up stale private state that
 * may otherwise stick around in memory.  Note that the
 * timer_control callback may be invoked from otrl_message_poll
 * itself, possibly to indicate that interval == 0 (that is, that
 * there's no more periodic work to be done at this time).
 *
 * If you set this callback to NULL, then you must ensure that your
 * application calls otrl_message_poll(userstate, uiops, uiopdata);
 * from the main libotr thread every definterval seconds (where
 * definterval can be obtained by calling
 * definterval = otrl_message_poll_get_default_interval(userstate);
 * right after creating the userstate).  The advantage of
 * implementing the timer_control callback is that the timer can be
 * turned on by libotr only when it's needed.
 *
 * It is not a problem (except for a minor performance hit) to call
 * otrl_message_poll more often than requested, whether
 * timer_control is implemented or not.
 *
 * If you fail to implement the timer_control callback, and also
 * fail to periodically call otrl_message_poll, then you open your
 * users to a possible forward secrecy violation: an attacker that
 * compromises the user's computer may be able to decrypt a handful
 * of long-past messages (the first messages of an OTR
 * conversation).
 */
static void timer_control_cb(void *opdata, unsigned int interval) {
  NSLog(@"timer_control_cb with interval : %d", interval);
  
  TBOTRManager *otrManager = [TBOTRManager sharedOTRManager];
  if (otrManager.pollTimer!=nil) {
    [otrManager.pollTimer invalidate];
    otrManager.pollTimer = nil;
  }
  
  if (interval > 0) {
    NSLog(@"timer_control_cb. setting a new timer : %d", interval);
    otrManager.pollTimer = [NSTimer scheduledTimerWithTimeInterval:interval
                                                            target:otrManager
                                                          selector:@selector(messagePoll)
                                                          userInfo:nil
                                                           repeats:YES];
  }
}

static OtrlMessageAppOps ui_ops = {
  policy_cb,
  create_privkey_cb,
  is_logged_in_cb,
  inject_message_cb,
  update_context_list_cb,
  confirm_fingerprint_received_cb,
  write_fingerprints_cb,
  gone_secure_cb,
  gone_insecure_cb,
  still_secure_cb,
  max_message_size_cb,
  account_display_name_cb,
  account_display_name_free_cb,
  received_symkey_cb,
  otr_error_message_cb,
  otr_error_message_free_cb,
  resent_msg_prefix_cb,
  resent_msg_prefix_free_cb,
  handle_smp_event_cb,
  handle_msg_event_cb,
  create_instag_cb,
  convert_data_cb,
  convert_data_free_cb,
  timer_control_cb
};

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
#pragma mark Initializer

///////////////////////////////////////////////////////////////////////////////////////////////////
+ (TBOTRManager *)sharedOTRManager {
  if (sharedOTRManager==nil) {
    sharedOTRManager = [[self alloc] init];
  }
  
  return sharedOTRManager;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
- (id)init {
  if (self=[super init]) {
    _pkCompletionBlocks = [NSMutableArray array];
    _nextMessageIsSignatureMessage = NO;
    _bgQueue = dispatch_queue_create([@"TBOTRManager bgQueue" UTF8String], DISPATCH_QUEUE_SERIAL);
    _isGeneratingPrivateKey = NO;
    
    // init otr lib
    OTRL_INIT;
    otr_userstate = otrl_userstate_create();
  }
  
  return self;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (void)reset {
  // delete the private key and instance tag
  NSFileManager *fileManager = [NSFileManager defaultManager];
  [fileManager removeItemAtPath:[[self class] privateKeyPath]  error:nil];
  [fileManager removeItemAtPath:[[self class] instanceTagPath]  error:nil];
    
  [self.pollTimer invalidate];
  self.pollTimer = nil;
  
  self.bgQueue = nil;
  
  if (self.isGeneratingPrivateKey) {
    otrl_privkey_generate_cancelled(otr_userstate, newkeyp);
  }
  
  otrl_privkey_pending_forget_all(otr_userstate);
  
  otrl_userstate_free(otr_userstate);
  otr_userstate = nil;
  
  sharedOTRManager = nil;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
#pragma mark Public Methods

////////////////////////////////////////////////////////////////////////////////////////////////////
- (NSString *)queryMessageForAccount:(NSString *)account {
  // Note that we pass a name for display, not internal usage
	char *msg = otrl_proto_default_query_msg([account UTF8String], OTRL_POLICY_DEFAULT);
  
	if (msg) {
    NSString *message = [NSString stringWithUTF8String:msg];
    free(msg);
    return message;
  }
  
  return @"";
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (void)generatePrivateKeyForAccount:(NSString *)account
                            protocol:(NSString *)protocol
                     completionBlock:(TBPrivateKeyCompletionBlock)completionBlock {
  const char *accountC = [account cStringUsingEncoding:NSUTF8StringEncoding];
  const char *protocolC = [protocol cStringUsingEncoding:NSUTF8StringEncoding];
  
  NSLog(@"!!! was asked to generate a private key");
  
  if (completionBlock!=NULL) {
    NSLog(@"!!! enqueuing the completion block");
    [self.pkCompletionBlocks addObject:completionBlock];
  }
  
  // if the private key already exist, execute the completion blocks and return
  OtrlPrivKey *privateKey = otrl_privkey_find(otr_userstate, accountC, protocolC);
  if (privateKey) {
    NSLog(@"!!! a private key already exist, will return");
    NSLog(@"!!! executing the completion block, (%d) pending", [self.pkCompletionBlocks count]);
    for (TBPrivateKeyCompletionBlock aBlock in self.pkCompletionBlocks) {
      aBlock();
    }
    self.pkCompletionBlocks = [NSMutableArray array];
    return;
  }
  
  /* Begin a private key generation that will potentially take place in
   * a background thread.  This routine must be called from the main
   * thread.  It will set *newkeyp, which you can pass to
   * otrl_privkey_generate_calculate in a background thread.  If it
   * returns gcry_error(GPG_ERR_EEXIST), then a privkey creation for
   * this accountname/protocol is already in progress, and *newkeyp will
   * be set to NULL. */
  //__block void *newkeyp;
  gcry_error_t generateError;
  generateError = otrl_privkey_generate_start(otr_userstate, accountC, protocolC, &newkeyp);
  
  NSLog(@"!!! generateError : %d vs %d", generateError, gcry_error(GPG_ERR_EEXIST));
  
  // key is already being generated : keep the ocmpletionBlock for later and return
  if (generateError==gcry_error(GPG_ERR_EEXIST)) {
    NSLog(@"!!! a private key is already being generated");
    if (completionBlock!=NULL) {
      NSLog(@"!!! enqueuing the pending block while generating the pk");
      [self.pkCompletionBlocks addObject:completionBlock];
    }
    return;
  }
  
  self.isGeneratingPrivateKey = YES;

  // generate the private key on the backgorund thread
  dispatch_async(self.bgQueue, ^{
    NSLog(@"!!! will generate the private key on %@ thread",
          ([NSThread isMainThread] ? @"main" : @"bg"));
    
    /* Do the private key generation calculation.  You may call this from a
     * background thread.  When it completes, call
     * otrl_privkey_generate_finish from the _main_ thread. */
    otrl_privkey_generate_calculate(newkeyp);
    
    NSLog(@"!!! private key calculated");
    
    // on the main thread
    dispatch_sync(dispatch_get_main_queue(), ^{
      self.isGeneratingPrivateKey = NO;
      // if the OTRManager has been reset while generating the key, don't execute this
      if (self.bgQueue!=nil) {
        NSString *privateKeyPath = [[self class] privateKeyPath];
        NSLog(@"!!! private key path : %@", privateKeyPath);
        const char *privateKeyPathC = [privateKeyPath cStringUsingEncoding:NSUTF8StringEncoding];
        
        /* Call this from the main thread only.  It will write the newly created
         * private key into the given file and store it in the OtrlUserState. */
        otrl_privkey_generate_finish(otr_userstate, newkeyp, privateKeyPathC);
        
        NSLog(@"!!! finishing the private key generation on %@ thread",
              ([NSThread isMainThread] ? @"main" : @"bg"));
        
        // execute the pending completion blocks
        NSLog(@"!!! executing the completion block, (%d) pending", [self.pkCompletionBlocks count]);
        for (TBPrivateKeyCompletionBlock aBlock in self.pkCompletionBlocks) {
          aBlock();
        }
        self.pkCompletionBlocks = [NSMutableArray array];
      }
      else {
        NSLog(@"!!! will not finish the private key generation");
      }
    });
  });
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (void)encodeMessage:(NSString *)message
            recipient:(NSString *)recipient
          accountName:(NSString *)accountName
             protocol:(NSString *)protocol
      completionBlock:(TBMessageEncodingCompletionBlock)completionBlock {
  [self generatePrivateKeyForAccount:accountName
                            protocol:protocol
                     completionBlock:^
   {
     ConnContext *context = [self contextForUsername:recipient
                                         accountName:accountName
                                            protocol:protocol];
     gcry_error_t err;
     char *newMessageC = NULL;
     
     NSLog(@"-- will encode message from %@ to %@", accountName, recipient);
     err = otrl_message_sending(otr_userstate, &ui_ops, NULL,
                                [accountName UTF8String], [protocol UTF8String],
                                [recipient UTF8String], OTRL_INSTAG_BEST, [message UTF8String],
                                NULL, &newMessageC, OTRL_FRAGMENT_SEND_SKIP, &context,
                                NULL, NULL);
     if (err!=GPG_ERR_NO_ERROR) {
       NSLog(@"!!!!! error while sending the message : %d", err);
     }
     
     if (err==GPG_ERR_NO_ERROR && !newMessageC) {
       NSLog(@"!!!!! There was no error, but an OTR message could not be made.\
             perhaps you need to run some key authentication first...");
     }
     
     NSString *newMessage = @"";
     if (newMessageC) {
       newMessage = [NSString stringWithUTF8String:newMessageC];
     }
     
     otrl_message_free(newMessageC);
     
     NSLog(@"-- org message : %@", message);
     NSLog(@"-- encrypted message : %@", newMessage);

     completionBlock(newMessage);
   }];
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (NSString *)decodeMessage:(NSString *)message
                     sender:(NSString *)sender
                accountName:(NSString *)accountName
                   protocol:(NSString *)protocol {
  if (![message length] || ![sender length] ||
      ![accountName length] || ![protocol length]) return @"";
  
  char *newMessageC = NULL;
  ConnContext *context = [self contextForUsername:sender
                                      accountName:accountName
                                         protocol:protocol];
  
  BOOL isInternalProtocolMsg = otrl_message_receiving(otr_userstate, &ui_ops, NULL,
                                                      [accountName UTF8String],
                                                      [protocol UTF8String],
                                                      [sender UTF8String],
                                                      [message UTF8String],
                                                      &newMessageC, NULL,
                                                      &context, NULL, NULL);
  NSString *newMessage = @"";
  
  //    if (context) {
  //      if (context->msgstate == OTRL_MSGSTATE_FINISHED) {
  //        [self disableEncryptionForUsername:recipient accountName:accountName protocol:protocol];
  //      }
  //    }
  
  if (isInternalProtocolMsg) {
    NSLog(@"-- %@ was an internal protocol message", message);
  }
  else {
    if (newMessageC) {
      newMessage = [NSString stringWithUTF8String:newMessageC];
      NSLog(@"-- message has been decrypted : %@", newMessage);
    }
    else {
      newMessage = message;
      NSLog(@"-- message wasn't an OTR message : %@", newMessage);
    }
  }
  otrl_message_free(newMessageC);
  
  return newMessage;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (NSString *)fingerprintForAccountName:(NSString *)accountName protocol:(NSString *)protocol {
  NSLog(@"asking fingerprint for %@", accountName);
  NSString *fingerprintString = nil;
  char our_hash[45];
  otrl_privkey_fingerprint(otr_userstate, our_hash, [accountName UTF8String], [protocol UTF8String]);
  fingerprintString = [NSString stringWithUTF8String:our_hash];
  return fingerprintString;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (NSString *)fingerprintForRecipient:(NSString *)recipient
                          accountName:(NSString *)accountName
                             protocol:(NSString *)protocol {
  Fingerprint * fingerprint = nil;
  ConnContext *context = [self contextForUsername:recipient
                                      accountName:accountName
                                         protocol:protocol];
  if(context) {
    fingerprint = context->active_fingerprint;
  }
  
  char their_hash[45];
  if(fingerprint && fingerprint->fingerprint) {
    otrl_privkey_hash_to_human(their_hash, fingerprint->fingerprint);
    return [NSString stringWithUTF8String:their_hash];
  }
  else {
    return nil;
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (BOOL)isConversationEncryptedForAccountName:(NSString *)accountName
                                    recipient:(NSString *)recipient
                                     protocol:(NSString *)protocol {
  ConnContext *context = [self contextForUsername:recipient
                                      accountName:accountName
                                         protocol:protocol];
  if (!context) return NO;
  
  BOOL isEncrypted = NO;
  switch (context->msgstate) {
    case OTRL_MSGSTATE_ENCRYPTED:
      isEncrypted = YES;
      break;
    case OTRL_MSGSTATE_FINISHED:
      isEncrypted = NO;
      break;
    case OTRL_MSGSTATE_PLAINTEXT:
      isEncrypted = NO;
      break;
    default:
      isEncrypted = NO;
      break;
  }
  
  return isEncrypted;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (void)disconnectRecipient:(NSString *)recipient
             forAccountName:(NSString *)accountName
                   protocol:(NSString *)protocol {
  otrl_message_disconnect_all_instances(otr_userstate, &ui_ops, NULL,
                                        [accountName UTF8String], [protocol UTF8String],
                                        [recipient UTF8String]);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
#pragma mark Private Methods

////////////////////////////////////////////////////////////////////////////////////////////////////
+ (NSString *)documentsDirectory {
  NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
  return [paths objectAtIndex:0];
}

////////////////////////////////////////////////////////////////////////////////////////////////////
+ (NSString *)privateKeyPath {
  return [[self documentsDirectory] stringByAppendingPathComponent:@"private-key"];
}

////////////////////////////////////////////////////////////////////////////////////////////////////
+ (NSString *)instanceTagPath {
  return [[self documentsDirectory] stringByAppendingPathComponent:@"instance-tag"];
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (ConnContext *)contextForUsername:(NSString *)username
                        accountName:(NSString *)accountName
                           protocol:(NSString *) protocol {
  ConnContext *context = otrl_context_find(otr_userstate, [username UTF8String],
                                           [accountName UTF8String], [protocol UTF8String],
                                           OTRL_INSTAG_BEST, NO,NULL,NULL, NULL);
  return context;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (void) messagePoll {
  otrl_message_poll(otr_userstate, &ui_ops, NULL);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
- (void)updateEncryptionStatusWithContext:(ConnContext*)context {
  if ([self.delegate respondsToSelector:
       @selector(OTRManager:didUpdateEncryptionStatus:forRecipient:accountName:protocol:)]) {
    NSString *accountName = [NSString stringWithUTF8String:context->accountname];
    NSString *recipient = [NSString stringWithUTF8String:context->username];
    NSString *protocol = [NSString stringWithUTF8String:context->protocol];
    BOOL isEncrypted = [self isConversationEncryptedForAccountName:accountName
                                                         recipient:recipient
                                                          protocol:protocol];
    [self.delegate OTRManager:self
    didUpdateEncryptionStatus:isEncrypted
                 forRecipient:recipient
                  accountName:accountName
                     protocol:protocol];
  }
}


@end
