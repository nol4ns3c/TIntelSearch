import nest_asyncio
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, Application, CallbackQueryHandler, ConversationHandler
from scan import *
from scanport import *
from urlscan import *
async def start(update, context):
     await update.message.reply_text("For usage use /help command")

async def help(update, context):
    await update.message.reply_text("""
    Usage :
        /ipscan [IP]     -   To scan ip address     
        /ipscan 8.8.8.8
        
        /urlscan [URl]   -   To scan url address    
        /urlscan https://google.com
    """)
nest_asyncio.apply()


async def ipscan(update: Update, context)  :
    global ip

    ip = context.args[0]
    global raw_result
    result,raw_result = res(ip)
    """Sends a message with three inline buttons attached."""

    keyboard = [

        [

            InlineKeyboardButton("Details", callback_data="1"),

            InlineKeyboardButton("Nmap Scan", callback_data="2"),


        ],
        [InlineKeyboardButton("Open Virustotal result In Browser", url="https://www.virustotal.com/gui/ip-address/" + ip)],
        [InlineKeyboardButton("Open AbuseIP result In Browser", url="https://www.abuseipdb.com/check/" + ip)],
]



    reply_markup = InlineKeyboardMarkup(keyboard)


    await update.message.reply_text(" Scanning ip address... ")
    await update.message.reply_text(result, reply_markup=reply_markup)

async def urlscan(update: Update, context)  :
    global url
    url = context.args[0]
    global raw_result_url
    global response_url
    result_url,raw_result_url,response_url = res_url(url)

    keyboard = [

        [

            InlineKeyboardButton("Details", callback_data="3"),


        ],[InlineKeyboardButton("Open VirusTotal result In Browser", url="https://www.virustotal.com/gui/home/url"),
],[InlineKeyboardButton("Open UrlScan result In Browser", url=response_url )]
]

    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(" Scanning url address... ")
    await update.message.reply_text(result_url, reply_markup=reply_markup)

async def button(update: Update,  context)  :

    query = update.callback_query
    if query.data == '1':
        await query.edit_message_text(raw_result)

    elif query.data == '2':
        await query.edit_message_text('Scanning port...')
        result = portscan(ip)
        await query.edit_message_text(result)
    elif query.data == '3':

        await query.edit_message_text(raw_result_url)


    await query.answer()


async def hello(update: Update, context) :
    await update.message.reply_text(f'Hello {update.effective_user.first_name}')

def main():
    app = ApplicationBuilder().token('[API-KEY]').build()
    app.add_handler(CommandHandler('start',start))
    app.add_handler(CommandHandler('ipscan',ipscan))
    app.add_handler(CommandHandler('urlscan',urlscan))
    app.add_handler(CommandHandler('help',help))
    app.add_handler(CommandHandler('hello',hello))
    app.add_handler(CallbackQueryHandler(button))
    app.run_polling()


main()
