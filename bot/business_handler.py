from telegram import Update
from telegram.ext import ContextTypes


async def handle_business_message(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):
    message = update.business_message

    if message is None:
        return

    connection_id = message.business_connection_id

    if not message.document:
        return

    document = message.document

    await context.bot.send_message(
        chat_id=message.chat_id,
        text=(
            "🛡️ KhmerShield-AI received a file.\n"
            "Security scanning integration is being prepared."
        ),
        business_connection_id=connection_id,
    )