from django.urls import reverse, resolve
from django.contrib.auth.forms import UserCreationForm, User
from django.test import TestCase
from .views import signup
from .forms import SignUpForm

class SignUpTests(TestCase):
    def setUp(self):
        url = reverse('signup')
        self.response = self.client.get(url)


    def test_signup_status_code(self):
        self.assertEquals(self.response.status_code, 200)


    def test_signup_url_resolves_signup_view(self):
        view = resolve('/signup/')
        self.assertEquals(view.func, signup)


    def test_csrf(self):
        self.assertContains(self.response, 'csrfmiddlewaretoken')


    def test_contains_form(self):
        form = self.response.context.get('form')
        self.assertIsInstance(form, SignUpForm)


class SuccessfulSignUpTests(TestCase):
    def setUp(self):
        url = reverse('signup')
        data = {
            'username': 'john',
            'email': 'john@doe.com',
            'password1': 'abcdef123456',
            'password2': 'abcdef123456',
            'security_question': 'Whats my name?',
            'answer': 'john'

        }
        self.response = self.client.post(url, data)
        self.home_url = reverse('home')

    def test_redirection(self):
        '''
        A valid form submission should redirect the user to the home page
        '''
        self.assertRedirects(self.response, self.home_url)

    def test_user_creation(self):
        self.assertTrue(User.objects.exists())

    def test_user_authentication(self):
        '''
        Create a new request to an arbitrary page.
        The resulting response should now have a `user` to its context,
        after a successful sign up.
        '''
        response = self.client.get(self.home_url)
        user = response.context.get('user')
        self.assertTrue(user.is_authenticated)


class InvalidSignUpTests(TestCase):
    def setUp(self):
        url = reverse('signup')
        self.response = self.client.post(url, {})  # submit an empty dictionary


    def test_signup_status_code(self):
        '''
        An invalid form submission should return to the same page
        '''
        self.assertEquals(self.response.status_code, 200)


    def test_form_errors(self):
        form = self.response.context.get('form')
        self.assertTrue(form.errors)


    def test_dont_create_user(self):
        self.assertFalse(User.objects.exists())


    def test_form_inputs(self):
        '''
        The view must contain seven inputs: csrf, username, email,
        password1, password2, question, answer
        '''
        self.assertContains(self.response, '<input', 7)
        self.assertContains(self.response, 'type="text"', 3)
        self.assertContains(self.response, 'type="email"', 1)
        self.assertContains(self.response, 'type="password"', 2)


class SignUpFormTest(TestCase):
    def test_form_has_fields(self):
        form = SignUpForm()
        expected = ['username', 'email', 'password1', 'password2', 'security_question', 'answer',]
        actual = list(form.fields)
        self.assertSequenceEqual(expected, actual)