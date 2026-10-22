import os
import json
import uuid
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

import httpx

from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)

from telegram.constants import ChatAction

from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    CallbackQueryHandler,
    filters,
)


# ============================================================
# CONFIGURATION
# ============================================================

API_URL = "http://127.0.0.1:8000/api/scan"

MAX_FILE_SIZE = 20 * 1024 * 1024

# Always save reports inside the KhmerShield-AI project
PROJECT_ROOT = Path(__file__).resolve().parents[1]

REPORTS_DIR = PROJECT_ROOT / "reports"

CASES_FILE = REPORTS_DIR / "telegram_cases.jsonl"


# ============================================================
# KHMER TEXT HELPERS
# ============================================================

RISK_NAMES = {
    "CRITICAL": "ខ្ពស់បំផុត",
    "HIGH": "ខ្ពស់",
    "MEDIUM": "មធ្យម",
    "LOW": "ទាប",
    "UNKNOWN": "មិនស្គាល់",
}


def khmer_risk_name(level: str) -> str:
    return RISK_NAMES.get(
        level.upper(),
        "មិនស្គាល់"
    )


# ============================================================
# FORMAT SCAN RESULT
# ============================================================

def format_result(result: dict) -> str:

    risk = result.get(
        "risk",
        {}
    )

    level = str(
        risk.get("level")
        or risk.get("risk_level")
        or "UNKNOWN"
    ).upper()

    score = risk.get(
        "score",
        0
    )

    filename = result.get(
        "filename",
        "មិនស្គាល់"
    )

    # --------------------------------------------------------
    # RISK MESSAGE
    # --------------------------------------------------------

    if level == "CRITICAL":

        emoji = "🔴"

        title = (
            "ឯកសារមានហានិភ័យខ្ពស់បំផុត"
        )

        recommendation = (
            "❌ សូមកុំបើក ឬដំណើរការឯកសារនេះ។"
        )

    elif level == "HIGH":

        emoji = "🔴"

        title = (
            "ឯកសារមានហានិភ័យខ្ពស់"
        )

        recommendation = (
            "❌ សូមកុំបើក ឬដំណើរការឯកសារនេះ។"
        )

    elif level == "MEDIUM":

        emoji = "🟡"

        title = (
            "ឯកសារត្រូវការការប្រុងប្រយ័ត្ន"
        )

        recommendation = (
            "⚠️ សូមកុំបើកឯកសារ "
            "ប្រសិនបើអ្នកមិនទុកចិត្តអ្នកផ្ញើ។"
        )

    else:

        emoji = "🟢"

        title = (
            "មិនបានរកឃើញការគំរាមកំហែងដែលស្គាល់"
        )

        recommendation = (
            "ℹ️ ប្រព័ន្ធមិនបានរកឃើញ "
            "ការគំរាមកំហែងដែលស្គាល់ "
            "តាមរយៈការស្កេនបច្ចុប្បន្នទេ។"
        )

    # --------------------------------------------------------
    # BASIC RESULT
    # --------------------------------------------------------

    lines = [

        "🛡️ KHMER SHIELD AI",

        "",

        f"{emoji} {title}",

        "",

        f"⚠️ កម្រិតហានិភ័យ៖ "
        f"{khmer_risk_name(level)}",

        f"📊 ពិន្ទុហានិភ័យ៖ "
        f"{score}/100",

        "",

        f"📄 ឯកសារ៖ {filename}",
    ]

    # --------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------

    findings = result.get(
        "findings",
        []
    )

    if findings:

        lines.append("")

        lines.append(
            "🔎 អ្វីដែលប្រព័ន្ធបានរកឃើញ៖"
        )

        for finding in findings[:6]:

            if isinstance(
                finding,
                dict
            ):

                finding_type = finding.get(
                    "type",
                    ""
                )

                message = (
                    finding.get("message")
                    or finding.get("description")
                    or finding.get("type")
                    or str(finding)
                )

                # ------------------------------------------------
                # YARA
                # ------------------------------------------------

                if finding_type == "yara_match":

                    message = (
                        "បានរកឃើញលំនាំគួរឱ្យសង្ស័យ "
                        "តាមរយៈប្រព័ន្ធសុវត្ថិភាព YARA"
                    )

                # ------------------------------------------------
                # CLAMAV
                # ------------------------------------------------

                elif (
                    finding_type == "clamav_detection"
                    or "clamav" in finding_type.lower()
                ):

                    message = (
                        "កម្មវិធីស្កេនមេរោគ "
                        "បានរកឃើញលក្ខណៈគួរឱ្យសង្ស័យ"
                    )

                # ------------------------------------------------
                # SUSPICIOUS EXTENSION
                # ------------------------------------------------

                elif (
                    finding_type == "suspicious_extension"
                ):

                    message = (
                        "ប្រភេទឯកសារនេះ "
                        "អាចមានហានិភ័យ"
                    )

                # ------------------------------------------------
                # DOUBLE EXTENSION
                # ------------------------------------------------

                elif (
                    "double" in finding_type.lower()
                ):

                    message = (
                        "ឈ្មោះឯកសារមានផ្នែកបន្ថែម "
                        "ច្រើនជាន់ ដែលអាចគួរឱ្យសង្ស័យ"
                    )

            else:

                message = str(
                    finding
                )

            lines.append(
                f"• {message}"
            )

    # --------------------------------------------------------
    # NETWORK INDICATORS
    # --------------------------------------------------------

    indicators = result.get(
        "indicators",
        {}
    )

    urls = indicators.get(
        "urls",
        []
    )

    domains = indicators.get(
        "domains",
        []
    )

    ips = indicators.get(
        "ips",
        []
    )

    if urls or domains or ips:

        lines.append("")

        lines.append(
            "🌐 ព័ត៌មានបណ្តាញដែលបានរកឃើញ៖"
        )

        if urls:

            lines.append(
                f"• តំណភ្ជាប់ (URLs)៖ "
                f"{len(urls)}"
            )

        if domains:

            lines.append(
                f"• ដែន (Domains)៖ "
                f"{len(domains)}"
            )

        if ips:

            lines.append(
                f"• អាសយដ្ឋាន IP៖ "
                f"{len(ips)}"
            )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    lines.extend(
        [
            "",
            recommendation,
            "",
            "🔐 សុវត្ថិភាពរបស់អ្នកសំខាន់។",
        ]
    )

    return "\n".join(lines)


# ============================================================
# RESULT BUTTONS
# ============================================================

def build_result_keyboard(
    case_id: str
):

    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "🔍 ហេតុអ្វី?",
                    callback_data=f"why:{case_id}",
                ),

                InlineKeyboardButton(
                    "🚨 រាយការណ៍ Scam",
                    callback_data=f"report:{case_id}",
                ),
            ]
        ]
    )


# ============================================================
# SAVE CASE
# ============================================================

def save_case(
    result: dict,
    update: Update
) -> str:

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    case_id = (
        f"KS-{uuid.uuid4().hex[:8].upper()}"
    )

    risk = result.get(
        "risk",
        {}
    )

    user = update.effective_user

    chat = update.effective_chat

    message = update.effective_message

    case = {

        "case_id": case_id,

        "created_at": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "source": "telegram",

        "telegram": {

            "user_id": (
                user.id
                if user
                else None
            ),

            "username": (
                user.username
                if user
                else None
            ),

            "chat_id": (
                chat.id
                if chat
                else None
            ),

            "message_id": (
                message.message_id
                if message
                else None
            ),
        },

        "file": {

            "filename": result.get(
                "filename"
            ),

            "sha256": result.get(
                "sha256"
            ),
        },

        "risk": {

            "level": risk.get(
                "level"
            ),

            "score": risk.get(
                "score"
            ),
        },

        "findings": result.get(
            "findings",
            []
        ),

        "indicators": {

            "urls": (
                result.get(
                    "indicators",
                    {}
                ).get(
                    "urls",
                    []
                )
            ),

            "domains": (
                result.get(
                    "indicators",
                    {}
                ).get(
                    "domains",
                    []
                )
            ),

            "ips": (
                result.get(
                    "indicators",
                    {}
                ).get(
                    "ips",
                    []
                )
            ),
        },

        "reported": False,
    }

    with open(
        CASES_FILE,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            json.dumps(
                case,
                ensure_ascii=False
            )
            + "\n"
        )

    return case_id


# ============================================================
# /START
# ============================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    if not update.message:
        return

    await update.message.reply_text(

        "🛡️ សូមស្វាគមន៍មកកាន់ "
        "KhmerShield-AI\n\n"

        "🔐 KhmerShield-AI អាចជួយអ្នក "
        "ពិនិត្យឯកសារដែលអ្នកសង្ស័យថា "
        "អាចមានមេរោគ ឬមានហានិភ័យ។\n\n"

        "📎 សូមផ្ញើឯកសារមកទីនេះ "
        "ហើយប្រព័ន្ធនឹងស្កេនដោយស្វ័យប្រវត្តិ។\n\n"

        "📂 ប្រភេទឯកសារដែលអាចពិនិត្យ៖\n"
        "• ZIP\n"
        "• EXE\n"
        "• APK\n"
        "• PDF\n"
        "• TXT\n"
        "• ប្រភេទឯកសារផ្សេងៗដែលប្រព័ន្ធគាំទ្រ\n\n"

        "⚠️ ទំហំឯកសារអតិបរមា៖ 20 MB\n\n"

        "📌 ពាក្យបញ្ជា៖\n"
        "/start — ចាប់ផ្តើម\n"
        "/help — របៀបប្រើប្រាស់\n"
        "/mycases — មើលករណីរបស់អ្នក"
    )


# ============================================================
# /HELP
# ============================================================

async def help_command(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    if not update.message:
        return

    await update.message.reply_text(

        "🛡️ របៀបប្រើ KhmerShield-AI\n\n"

        "1️⃣ ផ្ញើ ឬ Forward ឯកសារ "
        "ដែលអ្នកសង្ស័យមកកាន់ Bot។\n\n"

        "2️⃣ KhmerShield នឹងទាញយកឯកសារ "
        "ហើយធ្វើការស្កេន។\n\n"

        "3️⃣ អ្នកនឹងទទួលបានលទ្ធផល "
        "និងកម្រិតហានិភ័យ។\n\n"

        "🔍 ហេតុអ្វី? — "
        "មើលមូលហេតុដែលឯកសារត្រូវបានសម្គាល់។\n\n"

        "🚨 រាយការណ៍ Scam — "
        "រក្សាទុកករណីសុវត្ថិភាព។\n\n"

        "⚠️ កុំបើកឯកសារដែលអ្នកសង្ស័យ "
        "គ្រាន់តែដើម្បីសាកល្បង។"
    )


# ============================================================
# HANDLE DOCUMENT
# ============================================================

async def handle_document(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    message = update.message

    if not message:
        return

    if not message.document:
        return

    document = message.document

    filename = (
        document.file_name
        or "unknown_file"
    )

    file_size = (
        document.file_size
        or 0
    )

    # --------------------------------------------------------
    # FILE SIZE
    # --------------------------------------------------------

    if file_size > MAX_FILE_SIZE:

        await message.reply_text(

            "⚠️ ឯកសារធំពេក\n\n"

            f"📄 ឯកសារ៖ {filename}\n"

            f"📦 ទំហំ៖ "
            f"{file_size / 1024 / 1024:.1f} MB\n\n"

            "KhmerShield បច្ចុប្បន្ន "
            "អាចពិនិត្យឯកសាររហូតដល់ 20 MB។"
        )

        return

    # --------------------------------------------------------
    # SCANNING MESSAGE
    # --------------------------------------------------------

    await message.chat.send_action(
        ChatAction.TYPING
    )

    status_message = (
        await message.reply_text(

            "🔍 KhmerShield "
            "កំពុងពិនិត្យឯកសារ...\n\n"

            f"📄 {filename}\n\n"

            "⏳ សូមរង់ចាំបន្តិច..."
        )
    )

    temp_path = None

    try:

        # ====================================================
        # DOWNLOAD FROM TELEGRAM
        # ====================================================

        telegram_file = (
            await context.bot.get_file(
                document.file_id
            )
        )

        # ====================================================
        # TEMPORARY FILE
        # ====================================================

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=Path(
                filename
            ).suffix,
        ) as temp_file:

            temp_path = (
                temp_file.name
            )

        # ====================================================
        # DOWNLOAD
        # ====================================================

        await telegram_file.download_to_drive(
            temp_path
        )

        # ====================================================
        # SEND TO KHMER SHIELD API
        # ====================================================

        with open(
            temp_path,
            "rb"
        ) as f:

            files = {

                "file": (
                    filename,
                    f,
                    document.mime_type
                    or "application/octet-stream",
                )
            }

            async with httpx.AsyncClient(
                timeout=120.0
            ) as client:

                response = await client.post(
                    API_URL,
                    files=files
                )

        # ====================================================
        # API RESPONSE
        # ====================================================

        response.raise_for_status()

        result = response.json()

        # ====================================================
        # FORMAT KHMER RESULT
        # ====================================================

        text = format_result(
            result
        )

        # ====================================================
        # SAVE SECURITY CASE
        # ====================================================

        case_id = save_case(
            result,
            update
        )

        # ====================================================
        # SEND RESULT
        # ====================================================

        await status_message.edit_text(

            text,

            reply_markup=(
                build_result_keyboard(
                    case_id
                )
            )
        )

    # ========================================================
    # HTTP ERROR
    # ========================================================

    except httpx.HTTPStatusError as exc:

        await status_message.edit_text(

            "❌ ប្រព័ន្ធស្កេនមានបញ្ហា\n\n"

            f"លេខកូដ៖ "
            f"{exc.response.status_code}\n\n"

            "សូមព្យាយាមម្តងទៀត។"
        )

    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception as exc:

        print(
            f"Telegram scan error: {exc}"
        )

        await status_message.edit_text(

            "❌ ការពិនិត្យឯកសារបរាជ័យ\n\n"

            "ប្រព័ន្ធមិនអាចពិនិត្យឯកសារនេះបានទេ។\n\n"

            "សូមព្យាយាមម្តងទៀត។"
        )

    # ========================================================
    # DELETE TEMP FILE
    # ========================================================

    finally:

        if temp_path:

            try:

                os.remove(
                    temp_path
                )

            except OSError:
                pass


# ============================================================
# BUTTON CALLBACK
# ============================================================

async def button_callback(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    query = update.callback_query

    if not query:
        return

    await query.answer()

    data = (
        query.data
        or ""
    )

    if ":" not in data:
        return

    action, case_id = (
        data.split(
            ":",
            1
        )
    )

    # ========================================================
    # WHY BUTTON
    # ========================================================

    if action == "why":

        await query.message.reply_text(

            "🔍 ហេតុអ្វីបានជា "
            "ឯកសារនេះត្រូវបានសម្គាល់?\n\n"

            f"🆔 លេខករណី៖ {case_id}\n\n"

            "KhmerShield បានរកឃើញ "
            "លក្ខណៈសុវត្ថិភាពដែលគួរឱ្យសង្ស័យ "
            "នៅក្នុងឯកសារ។\n\n"

            "មូលហេតុអាចរួមមាន៖\n"

            "• លំនាំឯកសារគួរឱ្យសង្ស័យ\n"

            "• YARA rule បានរកឃើញលំនាំ\n"

            "• មាតិកា Archive គួរឱ្យសង្ស័យ\n"

            "• កម្មវិធីស្កេនមេរោគបានរកឃើញបញ្ហា\n"

            "• មាន URL / Domain / IP គួរឱ្យសង្ស័យ\n\n"

            "❌ ប្រសិនបើអ្នកមិនស្គាល់អ្នកផ្ញើ "
            "សូមកុំបើកឯកសារ។\n\n"

            "⚠️ លទ្ធផលនេះមិនអាចបញ្ជាក់ថា "
            "អ្នកណាជាអ្នកផ្ញើឯកសារនោះបានទេ។"
        )

    # ========================================================
    # REPORT BUTTON
    # ========================================================

    elif action == "report":

        reported = mark_case_reported(
            case_id
        )

        if reported:

            await query.message.reply_text(

                "🚨 បានរក្សាទុករបាយការណ៍\n\n"

                f"🆔 លេខករណី៖ {case_id}\n\n"

                "ព័ត៌មានដែលបានរក្សាទុករួមមាន៖\n"

                "• ឈ្មោះឯកសារ\n"
                "• SHA-256\n"
                "• ពិន្ទុហានិភ័យ\n"
                "• លទ្ធផលការរកឃើញ\n"
                "• ពេលវេលាស្កេន\n"
                "• ព័ត៌មានសារ Telegram ដែលមាន\n\n"

                "📌 អ្នកអាចរក្សាទុកលេខករណីនេះ "
                "សម្រាប់ពិនិត្យនៅពេលក្រោយ។"
            )

        else:

            await query.message.reply_text(

                "❌ មិនអាចរក្សាទុករបាយការណ៍បានទេ។\n\n"

                f"លេខករណី៖ {case_id}"
            )


# ============================================================
# MARK CASE AS REPORTED
# ============================================================

def mark_case_reported(
    case_id: str
) -> bool:

    if not CASES_FILE.exists():
        return False

    updated_cases = []

    found = False

    try:

        with open(
            CASES_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:

                if not line.strip():
                    continue

                try:

                    case = json.loads(
                        line
                    )

                except json.JSONDecodeError:

                    continue

                if case.get(
                    "case_id"
                ) == case_id:

                    case[
                        "reported"
                    ] = True

                    case[
                        "reported_at"
                    ] = (
                        datetime.now(
                            timezone.utc
                        ).isoformat()
                    )

                    found = True

                updated_cases.append(
                    case
                )

        # ----------------------------------------------------
        # Rewrite JSONL
        # ----------------------------------------------------

        with open(
            CASES_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            for case in updated_cases:

                f.write(
                    json.dumps(
                        case,
                        ensure_ascii=False
                    )
                    + "\n"
                )

        return found

    except Exception as exc:

        print(
            f"Case update error: {exc}"
        )

        return False


# ============================================================
# /MYCASES
# ============================================================

async def my_cases(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    user = update.effective_user

    if not user:
        return

    # --------------------------------------------------------
    # NO CASE FILE
    # --------------------------------------------------------

    if not CASES_FILE.exists():

        await update.message.reply_text(

            "📂 អ្នកមិនទាន់មានករណី "
            "ដែលបានរក្សាទុកទេ។"
        )

        return

    cases = []

    try:

        with open(
            CASES_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:

                if not line.strip():
                    continue

                try:

                    case = json.loads(
                        line
                    )

                except json.JSONDecodeError:

                    continue

                telegram_data = case.get(
                    "telegram",
                    {}
                )

                if (
                    telegram_data.get(
                        "user_id"
                    )
                    == user.id
                ):

                    cases.append(
                        case
                    )

    except Exception as exc:

        print(
            f"Case read error: {exc}"
        )

        await update.message.reply_text(

            "❌ មិនអាចបើកបញ្ជីករណីបានទេ។"
        )

        return

    # --------------------------------------------------------
    # NO CASES
    # --------------------------------------------------------

    if not cases:

        await update.message.reply_text(

            "📂 អ្នកមិនទាន់មានករណី "
            "ដែលបានរក្សាទុកទេ។"
        )

        return

    # --------------------------------------------------------
    # LAST 10 CASES
    # --------------------------------------------------------

    cases = cases[-10:]

    lines = [

        "🛡️ ករណី KhmerShield របស់អ្នក",

        "",

    ]

    for case in reversed(
        cases
    ):

        risk = case.get(
            "risk",
            {}
        )

        file_data = case.get(
            "file",
            {}
        )

        level = str(
            risk.get(
                "level",
                "UNKNOWN"
            )
        ).upper()

        reported = case.get(
            "reported",
            False
        )

        if reported:

            report_status = (
                "🚨 បានរាយការណ៍"
            )

        else:

            report_status = (
                "📋 បានស្កេន"
            )

        lines.extend(

            [

                f"🆔 {case.get('case_id', 'Unknown')}",

                f"📄 {file_data.get('filename', 'Unknown')}",

                f"⚠️ កម្រិត៖ "
                f"{khmer_risk_name(level)}",

                f"📊 ពិន្ទុ៖ "
                f"{risk.get('score', 0)}/100",

                report_status,

                "",

            ]
        )

    await update.message.reply_text(
        "\n".join(lines)
    )


# ============================================================
# UNSUPPORTED MESSAGE
# ============================================================

async def handle_unsupported(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    if not update.message:
        return

    await update.message.reply_text(

        "🛡️ KhmerShield-AI\n\n"

        "📎 សូមផ្ញើឯកសារ "
        "ដែលអ្នកចង់ឱ្យប្រព័ន្ធពិនិត្យ។\n\n"

        "ឧទាហរណ៍៖\n"
        "• ZIP\n"
        "• PDF\n"
        "• APK\n"
        "• EXE\n"
        "• TXT"
    )


# ============================================================
# ERROR HANDLER
# ============================================================

async def error_handler(
    update: object,
    context: ContextTypes.DEFAULT_TYPE
):

    print(
        f"Telegram error: {context.error}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    token = os.getenv(
        "TELEGRAM_BOT_TOKEN"
    )

    if not token:

        raise RuntimeError(

            "TELEGRAM_BOT_TOKEN "
            "environment variable is missing."
        )

    # --------------------------------------------------------
    # CREATE TELEGRAM APPLICATION
    # --------------------------------------------------------

    application = (
        Application
        .builder()
        .token(token)
        .build()
    )

    # --------------------------------------------------------
    # COMMANDS
    # --------------------------------------------------------

    application.add_handler(
        CommandHandler(
            "start",
            start
        )
    )

    application.add_handler(
        CommandHandler(
            "help",
            help_command
        )
    )

    application.add_handler(
        CommandHandler(
            "mycases",
            my_cases
        )
    )

    # --------------------------------------------------------
    # FILE / DOCUMENT HANDLER
    # --------------------------------------------------------

    application.add_handler(

        MessageHandler(
            filters.Document.ALL,
            handle_document
        )
    )

    # --------------------------------------------------------
    # BUTTON HANDLER
    # --------------------------------------------------------

    application.add_handler(

        CallbackQueryHandler(
            button_callback
        )
    )

    # --------------------------------------------------------
    # OTHER TEXT MESSAGES
    # --------------------------------------------------------

    application.add_handler(

        MessageHandler(
            filters.TEXT
            & ~filters.COMMAND,
            handle_unsupported
        )
    )

    # --------------------------------------------------------
    # ERROR HANDLER
    # --------------------------------------------------------

    application.add_error_handler(
        error_handler
    )

    # --------------------------------------------------------
    # START
    # --------------------------------------------------------

    print(
        "🛡️ KhmerShield-AI Telegram Bot started."
    )

    print(
        "🇰🇭 Khmer user interface enabled."
    )

    print(
        f"📂 Cases: {CASES_FILE}"
    )

    print(
        "Waiting for suspicious files..."
    )

    application.run_polling()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()