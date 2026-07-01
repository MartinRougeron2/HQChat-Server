enum MessageTypesToSent {
    AUTH_INIT = 'auth_init',
    AUTH_VERIFY = 'auth_verify',
    JOIN_ROOM = 'join_room',
    MESSAGE = 'message',
    IMAGE_MESSAGE = 'image_message',
    AUDIO_MESSAGE = 'audio_message',
    AUDIO_STREAM_START = 'audio_stream_start',
    AUDIO_STREAM_CHUNK = 'audio_stream_chunk',
    AUDIO_STREAM_END = 'audio_stream_end',
    AES = 'aes',
    GET_FRIENDS = 'get_friends',
    ADD_FRIEND = 'add_friend',   // Actually triggers DB.invite
    ACCEPT_INVITE = 'accept_invite',
    REMOVE_FRIEND = 'remove_friend',
    GET_INVITES = 'get_invites',
    ROOM_MESSAGE = 'room_message',
    SET_USERNAME = 'set_username',
    GET_USERNAME = 'get_username',
    GET_ALL_USERS = 'get_users',
    HEARTBEAT_PONG = 'heartbeat_pong', // Used to keep connection alive
    REGISTER_PUSH_TOKEN = 'register_push_token',
    CALL_INITIATE = 'call_initiate',
    CALL_ACCEPT = 'call_accept',
    CALL_REJECT = 'call_reject',
    CALL_END = 'call_end',
    CALL_MEDIA_CHUNK = 'call_media_chunk',
    DELETE_ACCOUNT = 'delete_account' // user-initiated, irreversible server-side purge
}

enum MessageTypesToReceive {
    // Auth Flow
    PAYMENT_REQUIRED = 'payment_required',
    AUTH_CHALLENGE = 'auth_challenge',
    SESSION_KEY = 'session_key', // dedicated HQC key exchange for transport encryption
    AUTH_SUCCESS = 'auth_success',
    AUTH_FAILED = 'auth_failed',

    // Friends
    USERNAME_RESPONSE = 'username_response',
    USERNAME_UPDATED = 'username_updated',
    FRIENDS_LIST = 'friends_list',
    INVITES_LIST = 'invites_list',
    FRIEND_ADDED = 'friend_added',
    FRIEND_REQUEST = 'friend_request',
    FRIEND_REMOVED = 'friend_removed',
    USER_LIST_RESPONSE = 'users',

    // Messaging
    ROOM_JOINED = 'room_joined',
    DIRECT_MESSAGE = 'direct_message',
    IMAGE_MESSAGE = 'image_message',
    AUDIO_MESSAGE = 'audio_message',
    AUDIO_STREAM_START = 'audio_stream_start',
    AUDIO_STREAM_CHUNK = 'audio_stream_chunk',
    AUDIO_STREAM_END = 'audio_stream_end',
    AES = 'aes',
    ROOM_MESSAGE = 'room_message',

    // Calls
    CALL_INCOMING = 'call_incoming',
    CALL_ACCEPTED = 'call_accepted',
    CALL_REJECTED = 'call_rejected',
    CALL_ENDED = 'call_ended',
    CALL_MEDIA_CHUNK = 'call_media_chunk',

    // Delivery receipts
    MESSAGE_DELIVERED = 'message_delivered',
    MESSAGE_QUEUED = 'message_queued',

    // System/Presence
    USER_ONLINE = 'user_online',
    USER_OFFLINE = 'user_offline',
    ERROR = 'error',
    HEARTBEAT_PING = 'heartbeat_ping',
    ACCOUNT_DELETED = 'account_deleted' // confirmation that the server purged the account
}

/**
 * Useful for frontend state management
 */
enum AuthSteps {
    INIT = 'INIT',
    CHALLENGE_SENT = 'CHALLENGE_SENT',
    AUTHENTICATED = 'AUTHENTICATED',
    FAILED = 'FAILED'
}

/**
 * Mapping specific error strings for UI consistency
 */
enum ErrorMessages {
    NOT_FRIENDS = 'NOT_FRIENDS',
    PEER_OFFLINE = 'PEER_OFFLINE',
    INVALID_PAYLOAD = 'INVALID_PAYLOAD',
    SUBSCRIPTION_EXPIRED = 'SUBSCRIPTION_EXPIRED',
    RATE_LIMITED = 'RATE_LIMITED'
}

export {
    MessageTypesToSent,
    MessageTypesToReceive,
    AuthSteps,
    ErrorMessages
}