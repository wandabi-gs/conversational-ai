from django.shortcuts import render, redirect
import openai
from decouple import config
from django.views import View
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from user.models import Chat
from django.http import JsonResponse, Http404

api_key = config('API_KEY')


class Register(View):
    template_name = "register.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('home')

        return render(request=request, template_name=self.template_name)

    def post(self, request):
        if request.user.is_authenticated:
            return redirect('home')

        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            User.objects.get(username=username)
            return render(request=request, template_name=self.template_name, context={'error': 'Username already exists'})

        except User.DoesNotExist:
            try:
                User.objects.get(email=email)
                return render(request=request, template_name=self.template_name, context={'error': 'Email already exists'})

            except User.DoesNotExist:
                if len(password) < 8:
                    return render(request=request, template_name=self.template_name, context={'error': 'Password must be at least 8 characters long'})

                else:
                    user = User.objects.create_user(
                        first_name=first_name, last_name=last_name, username=username, email=email, password=password)
                    user.save()
                    return redirect('login')


class Login(View):
    template_name = "login.html"

    def get(self, request):
        request.session.clear()
        if request.user.is_authenticated:
            return redirect('home')

        return render(request=request, template_name=self.template_name)

    def post(self, request):
        if request.user.is_authenticated:
            return redirect('home')

        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = User.objects.get(username=username)

            if authenticate(request=request, username=username, password=password):
                login(request=request, user=user)
                chats = Chat.objects.filter(user=user)

                conversation = []
                for chat in chats:
                    conversation.append({"role": "user", "content": chat.message})
                    conversation.append({"role": "assistant", "content": chat.response})

                request.session['conversation'] = conversation

                return redirect('home')

            else:
                return render(request=request, template_name=self.template_name, context={'error': 'Invalid login credentials'})

        except User.DoesNotExist:
            return render(request=request, template_name=self.template_name, context={'error': 'Invalid login credentials'})


class ChatbotView(View):
    system_msg = {}
    def post(self, request):
        self.system_msg = {
            "role": "system",
            "content": f"""
            You are a friend. Your name is {config('BOT_NAME')}.This users name is {request.user.last_name} {request.user.first_name}.
            You are having a vocal conversation with a user.
            Remember to be casual sneeking in one of this users name in the response once in a while.
            You will never output any markdown or formatted text of any kind, 
            and you will speak in a concise, friendly, casual and highly conversational manner. 
            You will also adopt any persona that the user may ask of you.
        """
        }

        if not request.user.is_authenticated:
            return redirect('login')

        conversation = request.session.get('conversation', [])
        user_input = request.POST.get('user_input')

        prompts = []

        if user_input:
            conversation.append({"role": "user", "content": user_input})

        send_convo = [self.system_msg]
        send_convo.extend(conversation[-10:])
        prompts.extend(send_convo)

        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=prompts,
                api_key=api_key
            )

            chatbot_replies = [message['message']['content']
                            for message in response['choices'] if message['message']['role'] == 'assistant']

            reply = chatbot_replies[0]
            conversation.append({"role": "assistant", "content": reply})
            Chat.objects.create(user=request.user, message=user_input, response = reply)

            request.session['conversation'] = conversation

            return JsonResponse({"response": reply})

        except Exception as e:
            print(e)
            print("#####################################################")
            return Http404()

    def get(self, request):
        if not request.user.is_authenticated:
            return redirect('login')

        conversation = request.session.get('conversation', [])
        return render(request, 'chat.html', {'conversation': conversation})


def Logout(request):
    request.session.clear()
    logout(request)
    return redirect('login')
