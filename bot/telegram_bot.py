import os
import json
import uuid
import tempfile
import html
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv

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
    BusinessConnectionHandler,
    filters,
)

# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

if not BOT_TOKEN:
    raise RuntimeError(
        "TELEGRAM_BOT_TOKEN is missing from .env"
    )

API_URL = "http://127.0.0.1:8000/api/scan"
URL_API_URL = "http://127.0.0.1:8000/api/scan-url"

MAX_FILE_SIZE = 20 * 1024 * 1024

PROJECT_ROOT = Path(__file__).resolve().parents[1]

REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

CASES_FILE = REPORTS_DIR / "telegram_cases.jsonl"

# ============================================================
# RISK NAMES
# ============================================================

RISK_NAMES = {
    "CRITICAL": "ខ្ពស់បំផុត",
    "HIGH": "ខ្ពស់",
    "MEDIUM": "មធ្យម",
    "LOW": "ទាប",
    "SAFE": "សុវត្ថិភាព",
    "UNKNOWN": "មិនស្គាល់",
}

# ============================================================
# UTILITIES
# ============================================================


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def generate_case_id():
    return f"KS-{uuid.uuid4().hex[:8].upper()}"


def get_nested(data, *keys, default=None):
    """
    Safely retrieve nested dictionary values.
    """

    current = data

    for key in keys:
        if not isinstance(current, dict):
            return default

        current = current.get(key)

        if current is None:
            return default

    return current


def risk_label(level):
    if not level:
        return "មិនស្គាល់"

    level = str(level).upper()

    return RISK_NAMES.get(
        level,
        str(level)
    )


def risk_emoji(level):

    level = str(level or "").upper()

    if level == "CRITICAL":
        return "🔴"

    if level == "HIGH":
        return "🟠"

    if level == "MEDIUM":
        return "🟡"

    if level in ("LOW", "SAFE"):
        return "🟢"

    return "⚪"


# ============================================================
# RESULT FORMATTER
# ============================================================


def format_result(result):

    if not isinstance(result, dict):
        return (
            "⚠️ KhmerShield-AI មិនអាចអានលទ្ធផលបានទេ។"
        )

    risk = result.get("risk", {})

    if not isinstance(risk, dict):
        risk = {}

    level = (
        risk.get("level")
        or risk.get("risk_level")
        or result.get("risk_level")
        or "UNKNOWN"
    )

    score = (
        risk.get("score")
        or risk.get("risk_score")
        or result.get("risk_score")
    )

    filename = (
        result.get("filename")
        or result.get("file_name")
        or "Unknown file"
    )

    emoji = risk_emoji(level)
    label = risk_label(level)

    lines = []

    lines.append("🛡️ <b>KhmerShield-AI Security Report</b>")
    lines.append("")
    lines.append(f"📄 <b>ឯកសារ:</b> {filename}")
    lines.append(
        f"{emoji} <b>កម្រិតហានិភ័យ:</b> {label}"
    )

    if score is not None:
        try:
            score_number = float(score)

            if score_number <= 1:
                score_number *= 100

            lines.append(
                f"📊 <b>Risk Score:</b> {score_number:.1f}%"
            )

        except (ValueError, TypeError):
            lines.append(
                f"📊 <b>Risk Score:</b> {score}"
            )

    lines.append("")

    # --------------------------------------------------------
    # Recommendation
    # --------------------------------------------------------

    level_upper = str(level).upper()

    if level_upper == "CRITICAL":

        lines.append(
            "🚨 <b>ការណែនាំ:</b>"
        )
        lines.append(
            "កុំបើក ឬដំណើរការឯកសារនេះ។ "
            "មានសញ្ញាហានិភ័យខ្ពស់បំផុត។"
        )

    elif level_upper == "HIGH":

        lines.append(
            "⚠️ <b>ការណែនាំ:</b>"
        )
        lines.append(
            "កុំបើកឯកសារ និងកុំផ្ញើព័ត៌មានសំខាន់ "
            "រហូតដល់បានផ្ទៀងផ្ទាត់អ្នកផ្ញើ។"
        )

    elif level_upper == "MEDIUM":

        lines.append(
            "⚠️ <b>ការណែនាំ:</b>"
        )
        lines.append(
            "ត្រូវប្រុងប្រយ័ត្ន និងផ្ទៀងផ្ទាត់ប្រភពឯកសារ។"
        )

    elif level_upper in ("LOW", "SAFE"):

        lines.append(
            "✅ <b>ការណែនាំ:</b>"
        )
        lines.append(
            "មិនរកឃើញសញ្ញាគួរឱ្យសង្ស័យសំខាន់ៗទេ "
            "ប៉ុន្តែសូមប្រុងប្រយ័ត្នជានិច្ច។"
        )

    else:

        lines.append(
            "ℹ️ <b>ការណែនាំ:</b>"
        )
        lines.append(
            "មិនអាចកំណត់កម្រិតហានិភ័យបានពេញលេញទេ។"
        )

    # --------------------------------------------------------
    # Findings
    # --------------------------------------------------------

    findings = result.get("findings")

    if findings:

        lines.append("")
        lines.append("🔎 <b>Findings</b>")

        if isinstance(findings, list):

            for item in findings[:10]:

                if isinstance(item, dict):

                    title = (
                        item.get("title")
                        or item.get("name")
                        or item.get("type")
                        or "Finding"
                    )

                    description = (
                        item.get("description")
                        or item.get("message")
                        or ""
                    )

                    if description:
                        lines.append(
                            f"• <b>{title}</b>: {description}"
                        )
                    else:
                        lines.append(
                            f"• {title}"
                        )

                else:
                    lines.append(
                        f"• {item}"
                    )

        elif isinstance(findings, str):

            lines.append(
                f"• {findings}"
            )

        else:

            lines.append(
                f"• {findings}"
            )

    # --------------------------------------------------------
    # YARA
    # --------------------------------------------------------

    yara = result.get("yara")

    if yara:

        lines.append("")
        lines.append("🧬 <b>YARA</b>")

        if isinstance(yara, list):

            for item in yara[:10]:
                lines.append(
                    f"• {item}"
                )

        elif isinstance(yara, dict):

            matches = (
                yara.get("matches")
                or yara.get("matched_rules")
                or []
            )

            if isinstance(matches, list):

                for match in matches[:10]:
                    lines.append(
                        f"• {match}"
                    )

            else:
                lines.append(
                    f"• {matches}"
                )

        else:

            lines.append(
                f"• {yara}"
            )

    # --------------------------------------------------------
    # ClamAV
    # --------------------------------------------------------

    clamav = result.get("clamav")

    if clamav:

        lines.append("")
        lines.append("🦠 <b>ClamAV</b>")

        if isinstance(clamav, dict):

            status = (
                clamav.get("status")
                or clamav.get("result")
                or "Unknown"
            )

            lines.append(
                f"• Status: {status}"
            )

            signature = (
                clamav.get("signature")
                or clamav.get("virus")
            )

            if signature:
                lines.append(
                    f"• Signature: {signature}"
                )

        else:

            lines.append(
                f"• {clamav}"
            )

    # --------------------------------------------------------
    # Suspicious extension
    # --------------------------------------------------------

    suspicious_extension = (
        result.get("suspicious_extension")
        or result.get("extension_suspicious")
    )

    if suspicious_extension:

        lines.append("")
        lines.append(
            "⚠️ <b>Suspicious Extension:</b>"
        )

        lines.append(
            f"• {suspicious_extension}"
        )

    # --------------------------------------------------------
    # Double extension
    # --------------------------------------------------------

    double_extension = (
        result.get("double_extension")
        or result.get("has_double_extension")
    )

    if double_extension:

        lines.append("")
        lines.append(
            "⚠️ <b>Double Extension:</b>"
        )

        lines.append(
            f"• {double_extension}"
        )

    # --------------------------------------------------------
    # Network indicators
    # --------------------------------------------------------

    network = result.get("network_indicators")

    if network:

        lines.append("")
        lines.append("🌐 <b>Network Indicators</b>")

        if isinstance(network, dict):

            urls = network.get("urls", [])
            domains = network.get("domains", [])
            ips = network.get("ips", [])

            if urls:
                lines.append(
                    f"• URLs: {len(urls)}"
                )

            if domains:
                lines.append(
                    f"• Domains: {len(domains)}"
                )

            if ips:
                lines.append(
                    f"• IP addresses: {len(ips)}"
                )

    # --------------------------------------------------------
    # Case footer
    # --------------------------------------------------------

    lines.append("")
    lines.append(
        "🔐 <i>KhmerShield-AI — Automated Security Analysis</i>"
    )

    return "\n".join(lines)


# ============================================================
# URL RESULT FORMATTER
# ============================================================


def format_url_result(result):
    if not isinstance(result, dict):
        return "⚠️ KhmerShield-AI មិនអាចអានលទ្ធផលបានទេ។"

    raw_url = result.get("url") or "Unknown URL"
    domain = result.get("domain") or ""
    level = str(result.get("risk_level") or "UNKNOWN").upper()
    score = result.get("risk_score", 0)
    verdict = result.get("verdict", "UNKNOWN")
    case_id = result.get("scan_id", "")
    recommendation = result.get("recommendation", "")
    findings = result.get("findings", [])

    emoji = risk_emoji(level)
    label = risk_label(level)

    lines = []
    lines.append("🛡️ <b>KHMERSHIELD URL SECURITY REPORT</b>")
    lines.append("")
    lines.append(f"🔗 <b>URL:</b> <code>{html.escape(raw_url)}</code>")
    if domain:
        lines.append(f"🌐 <b>Domain:</b> <code>{html.escape(domain)}</code>")
    lines.append(f"{emoji} <b>កម្រិតហានិភ័យ:</b> {label} ({level})")
    lines.append(f"📊 <b>Score:</b> {score}/100")
    lines.append(f"⚖️ <b>Verdict:</b> {html.escape(verdict)}")
    lines.append("")

    if findings:
        lines.append("🔎 <b>Findings:</b>")
        for f in findings[:6]:
            fname = f.get("finding") or "Finding"
            fsev = str(f.get("severity") or "low").upper()
            lines.append(f"• <b>[{fsev}]</b> {html.escape(fname)}")
        lines.append("")

    if recommendation:
        lines.append("🚨 <b>ការណែនាំ:</b>")
        lines.append(html.escape(recommendation))
        lines.append("")

    if case_id:
        lines.append(f"🆔 <b>Case ID:</b> <code>{case_id}</code>")

    lines.append("")
    lines.append("🔐 <i>KhmerShield-AI — Automated URL Intelligence</i>")

    return "\n".join(lines)


# ============================================================
# TELEGRAM METADATA
# ============================================================


def get_business_message(update):

    return getattr(
        update,
        "business_message",
        None
    )


def get_message_sender_info(message):

    user = getattr(
        message,
        "from_user",
        None
    )

    if not user:

        return {
            "user_id": None,
            "username": None,
            "first_name": None,
            "last_name": None,
        }

    return {
        "user_id": user.id,
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
    }


# ============================================================
# SAVE CASE
# ============================================================


def save_case(result, update, source="telegram"):

    case_id = generate_case_id()

    message = get_business_message(update)

    if message:

        source = "telegram_business"

        sender = get_message_sender_info(message)

        telegram_data = {
            "user_id": sender["user_id"],
            "username": sender["username"],
            "first_name": sender["first_name"],
            "last_name": sender["last_name"],
            "chat_id": (
                message.chat.id
                if message.chat
                else None
            ),
            "message_id": message.message_id,
            "business_connection_id": getattr(
                message,
                "business_connection_id",
                None
            ),
        }

    else:

        user = update.effective_user
        chat = update.effective_chat
        message_obj = update.effective_message

        telegram_data = {
            "user_id": user.id if user else None,
            "username": (
                user.username
                if user
                else None
            ),
            "first_name": (
                user.first_name
                if user
                else None
            ),
            "last_name": (
                user.last_name
                if user
                else None
            ),
            "chat_id": (
                chat.id
                if chat
                else None
            ),
            "message_id": (
                message_obj.message_id
                if message_obj
                else None
            ),
        }

    case = {
        "case_id": case_id,
        "timestamp": now_iso(),
        "source": source,
        "telegram": telegram_data,
        "result": result,
    }

    with CASES_FILE.open(
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                case,
                ensure_ascii=False
            )
            + "\n"
        )

    return case_id


# ============================================================
# KEYBOARD
# ============================================================


def build_result_keyboard(case_id):

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
# START
# ============================================================


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):

    text = (
        "🛡️ <b>ស្វាគមន៍មកកាន់ KhmerShield-AI</b>\n\n"
        "ប្រព័ន្ធនេះអាចជួយវិភាគឯកសារ "
        "និងរកសញ្ញាដែលអាចពាក់ព័ន្ធនឹង Scam ឬ Malware។\n\n"
        "📎 ផ្ញើឯកសារមកខ្ញុំដើម្បីស្កេន។\n\n"
        "ប្រសិនបើអ្នកកំពុងប្រើ Telegram Business "
        "Bot អាចជួយវិភាគសាររបស់អតិថិជន "
        "និងឯកសារដែលពួកគេផ្ញើ។"
    )

    await update.effective_message.reply_text(
        text,
        parse_mode="HTML",
    )


# ============================================================
# HELP
# ============================================================


async def help_command(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    text = (
        "🛡️ <b>KhmerShield-AI Help</b>\n\n"
        "🔗 <b>URL & Phishing Scan</b>\n"
        "វាយ <code>/scan &lt;url&gt;</code> ឬផ្ញើតំណភ្ជាប់ (URL) ដោយផ្ទាល់ "
        "ដើម្បីវិភាគរក Phishing, Scam, និង Fake Domain។\n\n"
        "📎 <b>File Scan</b>\n"
        "ផ្ញើ PDF, ZIP, DOCX, EXE ឬឯកសារផ្សេងៗ "
        "ដើម្បីវិភាគរកមេរោគ។\n\n"
        "🏢 <b>Telegram Business</b>\n"
        "Business account អាចភ្ជាប់ Bot "
        "ដើម្បីឱ្យ Bot ជួយត្រួតពិនិត្យ customer messages "
        "និង files ដោយស្វ័យប្រវត្តិ។\n\n"
        "📊 <b>/mycases</b>\n"
        "មើលចំនួន security cases ដែលបានរក្សាទុក។"
    )

    await update.effective_message.reply_text(
        text,
        parse_mode="HTML",
    )


# ============================================================
# SCAN URL COMMAND
# ============================================================


async def scan_url_command(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):
    message = update.effective_message
    if not message:
        return

    # Check argument
    if not context.args:
        await message.reply_text(
            "🛡️ <b>KhmerShield-AI URL Scanner</b>\n\n"
            "សូមបញ្ជាក់តំណភ្ជាប់ (URL) ដែលអ្នកចង់ស្កេន ឧទាហរណ៍៖\n"
            "<code>/scan https://example.com</code>\n\n"
            "ឬអ្នកអាចផ្ញើតំណភ្ជាប់ចូលក្នុង Chat ដោយផ្ទាល់។",
            parse_mode="HTML",
        )
        return

    target_url = context.args[0].strip()

    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id,
        action=ChatAction.TYPING,
    )

    wait_msg = await message.reply_text(
        f"🔍 កំពុងវិភាគតំណភ្ជាប់...\n<code>{html.escape(target_url)}</code>",
        parse_mode="HTML",
    )

    try:
        result = await scan_url_api(target_url)
        report_text = format_url_result(result)
        case_id = result.get("scan_id", "")
        keyboard = build_result_keyboard(case_id) if case_id else None

        await wait_msg.delete()
        await message.reply_text(
            report_text,
            reply_markup=keyboard,
            parse_mode="HTML",
        )
    except Exception as exc:
        await wait_msg.delete()
        await message.reply_text(
            f"❌ <b>ការវិភាគតំណភ្ជាប់បរាជ័យ</b>\n\n"
            f"Error: <code>{html.escape(str(exc))}</code>",
            parse_mode="HTML",
        )


# ============================================================
# MY CASES
# ============================================================


async def my_cases(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    if not CASES_FILE.exists():

        await update.effective_message.reply_text(
            "📊 មិនទាន់មាន security cases ទេ។"
        )

        return

    count = 0

    try:

        with CASES_FILE.open(
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                if line.strip():
                    count += 1

    except Exception:

        count = 0

    await update.effective_message.reply_text(
        f"📊 <b>KhmerShield-AI Cases</b>\n\n"
        f"Total cases: <b>{count}</b>",
        parse_mode="HTML",
    )


# ============================================================
# CALL API
# ============================================================


async def scan_file(file_path, filename):

    timeout = httpx.Timeout(
        120.0,
        connect=30.0,
    )

    async with httpx.AsyncClient(
        timeout=timeout
    ) as client:

        with open(
            file_path,
            "rb"
        ) as file:

            response = await client.post(
                API_URL,
                files={
                    "file": (
                        filename,
                        file,
                        "application/octet-stream",
                    )
                },
            )

        response.raise_for_status()

        return response.json()


# ============================================================
# CALL URL SCAN API
# ============================================================


async def scan_url_api(target_url: str):
    timeout = httpx.Timeout(
        30.0,
        connect=10.0,
    )

    async with httpx.AsyncClient(
        timeout=timeout
    ) as client:
        response = await client.post(
            URL_API_URL,
            json={
                "url": target_url,
                "source": "telegram",
            },
        )
        response.raise_for_status()
        return response.json()


# ============================================================
# DOWNLOAD TELEGRAM FILE
# ============================================================


async def download_telegram_file(
    context,
    file_id,
    destination
):

    telegram_file = await context.bot.get_file(
        file_id
    )

    await telegram_file.download_to_drive(
        destination
    )


# ============================================================
# NORMAL TELEGRAM DOCUMENT
# ============================================================


async def handle_document(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    message = update.effective_message

    if not message or not message.document:
        return

    document = message.document

    filename = (
        document.file_name
        or "unknown_file"
    )

    file_size = document.file_size or 0

    print("")
    print("📎 NORMAL TELEGRAM DOCUMENT")
    print(f"Filename: {filename}")
    print(f"File size: {file_size}")

    if file_size > MAX_FILE_SIZE:

        await message.reply_text(
            "❌ ឯកសារធំពេក។\n\n"
            "ទំហំអតិបរមា: 20 MB"
        )

        return

    status_message = await message.reply_text(
        "🛡️ KhmerShield-AI\n\n"
        "⏳ កំពុងទាញយក និងវិភាគឯកសារ..."
    )

    temp_path = None

    try:

        await context.bot.send_chat_action(
            chat_id=message.chat.id,
            action=ChatAction.TYPING,
        )

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=Path(filename).suffix
        ) as temp:

            temp_path = temp.name

        await download_telegram_file(
            context,
            document.file_id,
            temp_path
        )

        print(
            f"📥 File downloaded: {temp_path}"
        )

        result = await scan_file(
            temp_path,
            filename
        )

        case_id = save_case(
            result,
            update,
            source="telegram"
        )

        response_text = format_result(
            result
        )

        response_text += (
            f"\n\n🆔 <b>Case ID:</b> "
            f"<code>{case_id}</code>"
        )

        await status_message.edit_text(
            response_text,
            parse_mode="HTML",
            reply_markup=build_result_keyboard(
                case_id
            ),
        )

        print(
            f"✅ Scan complete: {case_id}"
        )

    except httpx.HTTPStatusError as error:

        print(
            f"❌ API HTTP error: {error}"
        )

        await status_message.edit_text(
            "❌ KhmerShield-AI API មានបញ្ហា។\n\n"
            "សូមពិនិត្យថា FastAPI server កំពុងដំណើរការ។"
        )

    except Exception as error:

        print(
            f"❌ Document error: {error}"
        )

        await status_message.edit_text(
            "❌ មិនអាចវិភាគឯកសារបានទេ។\n\n"
            f"<code>{str(error)[:500]}</code>",
            parse_mode="HTML",
        )

    finally:

        if temp_path:

            try:
                os.remove(temp_path)

            except OSError:
                pass


# ============================================================
# TELEGRAM BUSINESS DOCUMENT
# ============================================================


async def handle_business_document(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    message = update.business_message

    if not message:
        return

    document = message.document

    if not document:
        return

    filename = (
        document.file_name
        or "unknown_file"
    )

    file_size = document.file_size or 0

    business_connection_id = getattr(
        message,
        "business_connection_id",
        None
    )

    print("")
    print("=" * 60)
    print("🏢 TELEGRAM BUSINESS MESSAGE")
    print("=" * 60)
    print(
        f"Business Connection ID: "
        f"{business_connection_id}"
    )
    print(
        f"Chat ID: "
        f"{message.chat.id if message.chat else None}"
    )
    print(
        f"Message ID: "
        f"{message.message_id}"
    )
    print(
        f"Filename: {filename}"
    )
    print(
        f"File size: {file_size}"
    )
    print("=" * 60)

    if file_size > MAX_FILE_SIZE:

        await message.reply_text(
            "❌ ឯកសាររបស់អតិថិជនធំពេក។\n\n"
            "ទំហំអតិបរមា: 20 MB"
        )

        return

    status_message = await message.reply_text(
        "🛡️ <b>KhmerShield-AI</b>\n\n"
        "⏳ កំពុងពិនិត្យឯកសាររបស់អតិថិជន..."
        ,
        parse_mode="HTML",
    )

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=Path(filename).suffix
        ) as temp:

            temp_path = temp.name

        await download_telegram_file(
            context,
            document.file_id,
            temp_path
        )

        print(
            f"📥 Business file downloaded: "
            f"{temp_path}"
        )

        result = await scan_file(
            temp_path,
            filename
        )

        case_id = save_case(
            result,
            update,
            source="telegram_business"
        )

        response_text = format_result(
            result
        )

        response_text += (
            f"\n\n🆔 <b>Case ID:</b> "
            f"<code>{case_id}</code>"
        )

        await status_message.edit_text(
            response_text,
            parse_mode="HTML",
            reply_markup=build_result_keyboard(
                case_id
            ),
        )

        print(
            f"✅ Business scan complete: "
            f"{case_id}"
        )

    except httpx.HTTPStatusError as error:

        print(
            f"❌ Business API error: {error}"
        )

        await status_message.edit_text(
            "❌ KhmerShield-AI API មានបញ្ហា។\n\n"
            "សូមពិនិត្យ FastAPI server។"
        )

    except Exception as error:

        print(
            f"❌ Business document error: "
            f"{error}"
        )

        try:

            await status_message.edit_text(
                "❌ មិនអាចវិភាគឯកសារបានទេ។\n\n"
                f"<code>{str(error)[:500]}</code>",
                parse_mode="HTML",
            )

        except Exception:
            pass

    finally:

        if temp_path:

            try:
                os.remove(temp_path)

            except OSError:
                pass


# ============================================================
# BUSINESS TEXT
# ============================================================


async def handle_business_text(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    message = update.business_message

    if not message:
        return

    text = message.text or ""

    if not text.strip():
        return

    connection_id = getattr(
        message,
        "business_connection_id",
        None
    )

    print("")
    print("=" * 60)
    print("💬 TELEGRAM BUSINESS TEXT")
    print("=" * 60)
    print(
        f"Business Connection ID: "
        f"{connection_id}"
    )
    print(
        f"Chat ID: "
        f"{message.chat.id if message.chat else None}"
    )
    print(
        f"Message ID: "
        f"{message.message_id}"
    )
    print(
        f"Text: {text}"
    )
    print("=" * 60)

    # --------------------------------------------------------
    # Temporary scam keyword detector
    # --------------------------------------------------------

    suspicious_keywords = [
        "send money",
        "send payment",
        "pay now",
        "verify your account",
        "otp",
        "password",
        "crypto",
        "investment",
        "send payment first",
        "click this link",
        "urgent payment",
    ]

    text_lower = text.lower()

    matched = [
        keyword
        for keyword in suspicious_keywords
        if keyword in text_lower
    ]

    if not matched:
        return

    warning = (
        "⚠️ <b>KhmerShield-AI Alert</b>\n\n"
        "ប្រព័ន្ធបានរកឃើញពាក្យ/លំនាំ "
        "ដែលអាចត្រូវការការប្រុងប្រយ័ត្ន។\n\n"
        f"🔎 <b>Indicators:</b> "
        f"{', '.join(matched)}\n\n"
        "⚠️ សូមផ្ទៀងផ្ទាត់ការទូទាត់ "
        "និងអត្តសញ្ញាណអ្នកផ្ញើ មុនពេលបន្ត។"
    )

    try:

        await message.reply_text(
            warning,
            parse_mode="HTML",
        )

    except Exception as error:

        print(
            f"❌ Could not reply to Business message: "
            f"{error}"
        )


# ============================================================
# BUSINESS CONNECTION
# ============================================================


async def handle_business_connection(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    connection = update.business_connection

    if not connection:
        return

    print("")
    print("=" * 60)
    print("🏢 TELEGRAM BUSINESS CONNECTION")
    print("=" * 60)

    print(
        f"Connection ID: {connection.id}"
    )

    print(
        f"Enabled: {connection.is_enabled}"
    )

    user = connection.user

    if user:

        print(
            f"User ID: {user.id}"
        )

        print(
            f"Username: {user.username}"
        )

    print(
        f"Can read messages: "
        f"{connection.can_read_messages}"
    )

    print(
        f"Can reply: "
        f"{connection.can_reply}"
    )

    print("=" * 60)


# ============================================================
# CALLBACK BUTTONS
# ============================================================


async def button_callback(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    query = update.callback_query

    if not query:
        return

    await query.answer()

    data = query.data or ""

    if data.startswith("why:"):

        case_id = data.split(
            ":",
            1
        )[1]

        await query.message.reply_text(
            "🔍 <b>ហេតុអ្វី?</b>\n\n"
            f"Case ID: <code>{case_id}</code>\n\n"
            "KhmerShield-AI ប្រើ security analysis "
            "ដើម្បីពិនិត្យ file indicators, "
            "malware signatures, suspicious patterns "
            "និង risk signals។",
            parse_mode="HTML",
        )

        return

    if data.startswith("report:"):

        case_id = data.split(
            ":",
            1
        )[1]

        await query.message.reply_text(
            "🚨 <b>Case បានរាយការណ៍</b>\n\n"
            f"Case ID: <code>{case_id}</code>\n\n"
            "សូមរក្សាទុក transaction information "
            "និងព័ត៌មានអ្នកផ្ញើសម្រាប់ការផ្ទៀងផ្ទាត់បន្ថែម។",
            parse_mode="HTML",
        )

        return


# ============================================================
# UNSUPPORTED NORMAL TEXT
# ============================================================


async def handle_unsupported(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    message = update.effective_message

    if not message or not message.text:
        return

    # Don't respond to Business messages here.
    if update.business_message:
        return

    text = message.text.strip()

    # Detect if message contains a URL
    url_match = re.search(r"https?://\S+|www\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\S*", text)
    if url_match:
        target_url = url_match.group(0)

        await context.bot.send_chat_action(
            chat_id=update.effective_chat.id,
            action=ChatAction.TYPING,
        )

        wait_msg = await message.reply_text(
            f"🔍 រកឃើញតំណភ្ជាប់! កំពុងវិភាគសុវត្ថិភាព...\n<code>{html.escape(target_url)}</code>",
            parse_mode="HTML",
        )

        try:
            result = await scan_url_api(target_url)
            report_text = format_url_result(result)
            case_id = result.get("scan_id", "")
            keyboard = build_result_keyboard(case_id) if case_id else None

            await wait_msg.delete()
            await message.reply_text(
                report_text,
                reply_markup=keyboard,
                parse_mode="HTML",
            )
            return
        except Exception as exc:
            await wait_msg.delete()
            await message.reply_text(
                f"❌ <b>ការវិភាគតំណភ្ជាប់បរាជ័យ</b>\n\n"
                f"Error: <code>{html.escape(str(exc))}</code>",
                parse_mode="HTML",
            )
            return

    await message.reply_text(
        "🛡️ <b>KhmerShield-AI</b>\n\n"
        "📎 សូមផ្ញើឯកសារ (File) ដើម្បីស្កេន\n"
        "🔗 ឬផ្ញើតំណភ្ជាប់ (URL) ឧទាហរណ៍៖ <code>/scan https://example.com</code>\n\n"
        "វាយ /help ដើម្បីមើលព័ត៌មានជំនួយបន្ថែម។",
        parse_mode="HTML",
    )


# ============================================================
# ERROR HANDLER
# ============================================================


async def error_handler(
    update: object,
    context: ContextTypes.DEFAULT_TYPE
):

    print("")
    print("❌ TELEGRAM BOT ERROR")
    print("=" * 60)
    print(context.error)
    print("=" * 60)


# ============================================================
# MAIN
# ============================================================


def main():

    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .build()
    )

    # --------------------------------------------------------
    # Commands
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
            "scan",
            scan_url_command
        )
    )

    application.add_handler(
        CommandHandler(
            "mycases",
            my_cases
        )
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # BUSINESS HANDLERS MUST COME BEFORE
    # NORMAL DOCUMENT/TEXT HANDLERS
    # --------------------------------------------------------

    application.add_handler(
        MessageHandler(
            filters.UpdateType.BUSINESS_MESSAGE
            & filters.Document.ALL,
            handle_business_document
        )
    )

    application.add_handler(
        MessageHandler(
            filters.UpdateType.BUSINESS_MESSAGE
            & filters.TEXT,
            handle_business_text
        )
    )

    # --------------------------------------------------------
    # Telegram Business Connection
    # --------------------------------------------------------

    application.add_handler(
        BusinessConnectionHandler(
            handle_business_connection
        )
    )

    # --------------------------------------------------------
    # Normal Telegram document
    # --------------------------------------------------------

    application.add_handler(
        MessageHandler(
            filters.Document.ALL,
            handle_document
        )
    )

    # --------------------------------------------------------
    # Callback buttons
    # --------------------------------------------------------

    application.add_handler(
        CallbackQueryHandler(
            button_callback
        )
    )

    # --------------------------------------------------------
    # Normal text
    # --------------------------------------------------------

    application.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            handle_unsupported
        )
    )

    # --------------------------------------------------------
    # Error handler
    # --------------------------------------------------------

    application.add_error_handler(
        error_handler
    )

    print("")
    print("=" * 60)
    print("🛡️ KhmerShield-AI Telegram Bot")
    print("=" * 60)
    print("🇰🇭 Khmer user interface: ENABLED")
    print("🏢 Telegram Business: ENABLED")
    print("📎 Business document scanning: ENABLED")
    print("💬 Business text monitoring: ENABLED")
    print("🔍 File scanning API:")
    print(f"   {API_URL}")
    print("📁 Reports:")
    print(f"   {CASES_FILE}")
    print("⏳ Waiting for Telegram updates...")
    print("=" * 60)

    application.run_polling(
        allowed_updates=Update.ALL_TYPES
    )


# ============================================================
# ENTRY POINT
# ============================================================


if __name__ == "__main__":
    main()