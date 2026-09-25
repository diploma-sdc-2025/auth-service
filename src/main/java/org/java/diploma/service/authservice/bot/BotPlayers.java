package org.java.diploma.service.authservice.bot;

/**
 * Reserved fill-opponent id. Not stored in {@code users}, so rating updates are a no-op.
 * {@link org.java.diploma.service.authservice.controller.UserController} returns a normal-looking public profile.
 */
public final class BotPlayers {

    public static final int USER_ID = 1_000_001;
    public static final String USERNAME = "Mira";
    public static final int RATING = 1016;

    private BotPlayers() {}

    public static boolean isBot(int userId) {
        return userId == USER_ID;
    }
}
