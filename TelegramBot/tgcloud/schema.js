import { table, text, integer, boolean } from 'sdk/db';

// Telegram Serverless owns this SQLite database. It stores only bot-local
// operational state; AuthPlatform PostgreSQL remains authoritative for users,
// linked identities, devices, OAuth grants, and access tokens.
export const telegramBotUsers = table('telegram_bot_users', {
  telegramUserId: text('telegram_user_id').primaryKey(),
  chatId: text('chat_id').notNull(),
  languageCode: text('language_code'),
  notificationsEnabled: boolean('notifications_enabled').notNull().default(true),
  firstSeenAt: integer('first_seen_at').notNull(),
  lastSeenAt: integer('last_seen_at').notNull(),
});
