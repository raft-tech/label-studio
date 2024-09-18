"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.
"""
import logging
import requests
import re
from urllib.parse import urlsplit

import drf_yasg.openapi as openapi
from core.feature_flags import flag_set
from core.permissions import ViewClassPermission, all_permissions
from django.conf import settings
from django.http import Http404
from django.utils.decorators import method_decorator
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema
from ml.models import MLBackend
from ml.serializers import MLBackendSerializer, MLInteractiveAnnotatingRequest
from projects.models import Project, Task
from rest_framework import generics, status
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView
from core.settings.base import KF_API_URL, KF_USERNAME, KF_PASSWORD, KSERVE_TLS_VERIFY, KF_MODELS_API_URL

logger = logging.getLogger(__name__)


@method_decorator(
    name='post',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='Add ML Backend',
        operation_description="""
    Add an ML backend to a project using the Label Studio UI or by sending a POST request using the following cURL 
    command:
    ```bash
    curl -X POST -H 'Content-type: application/json' {host}/api/ml -H 'Authorization: Token abc123'\\
    --data '{{"url": "http://localhost:9090", "project": {{project_id}}}}' 
    """.format(
            host=(settings.HOSTNAME or 'https://localhost:8080')
        ),
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'project': openapi.Schema(type=openapi.TYPE_INTEGER, description='Project ID'),
                'url': openapi.Schema(type=openapi.TYPE_STRING, description='ML backend URL'),
            },
        ),
    ),
)
@method_decorator(
    name='get',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='List ML backends',
        operation_description="""
    List all configured ML backends for a specific project by ID.
    Use the following cURL command:
    ```bash
    curl {host}/api/ml?project={{project_id}} -H 'Authorization: Token abc123'
    """.format(
            host=(settings.HOSTNAME or 'https://localhost:8080')
        ),
        manual_parameters=[
            openapi.Parameter(
                name='project', type=openapi.TYPE_INTEGER, in_=openapi.IN_QUERY, description='Project ID'
            ),
        ],
    ),
)
class MLBackendListAPI(generics.ListCreateAPIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    permission_required = ViewClassPermission(
        GET=all_permissions.projects_view,
        POST=all_permissions.projects_change,
    )
    serializer_class = MLBackendSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['is_interactive']

    def get_queryset(self):
        project_pk = self.request.query_params.get('project')
        project = generics.get_object_or_404(Project, pk=project_pk)

        self.check_object_permissions(self.request, project)

        ml_backends = project.update_ml_backends_state()

        return ml_backends

    def perform_create(self, serializer):
        ml_backend = serializer.save()
        ml_backend.update_state()


@method_decorator(
    name='patch',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='Update ML Backend',
        operation_description="""
    Update ML backend parameters using the Label Studio UI or by sending a PATCH request using the following cURL command:
    ```bash
    curl -X PATCH -H 'Content-type: application/json' {host}/api/ml/{{ml_backend_ID}} -H 'Authorization: Token abc123'\\
    --data '{{"url": "http://localhost:9091"}}' 
    """.format(
            host=(settings.HOSTNAME or 'https://localhost:8080')
        ),
    ),
)
@method_decorator(
    name='get',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='Get ML Backend',
        operation_description="""
    Get details about a specific ML backend connection by ID. For example, make a GET request using the
    following cURL command:
    ```bash
    curl {host}/api/ml/{{ml_backend_ID}} -H 'Authorization: Token abc123'
    """.format(
            host=(settings.HOSTNAME or 'https://localhost:8080')
        ),
    ),
)
@method_decorator(
    name='delete',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='Remove ML Backend',
        operation_description="""
    Remove an existing ML backend connection by ID. For example, use the
    following cURL command:
    ```bash
    curl -X DELETE {host}/api/ml/{{ml_backend_ID}} -H 'Authorization: Token abc123'
    """.format(
            host=(settings.HOSTNAME or 'https://localhost:8080')
        ),
    ),
)
@method_decorator(name='put', decorator=swagger_auto_schema(auto_schema=None))
class MLBackendDetailAPI(generics.RetrieveUpdateDestroyAPIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    serializer_class = MLBackendSerializer
    permission_required = all_permissions.projects_change
    queryset = MLBackend.objects.all()

    def get_object(self):
        ml_backend = super(MLBackendDetailAPI, self).get_object()
        ml_backend.update_state()
        return ml_backend

    def perform_update(self, serializer):
        ml_backend = serializer.save()
        ml_backend.update_state()


@method_decorator(
    name='post',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='Train',
        operation_description="""
        After you add an ML backend, call this API with the ML backend ID to start training with 
        already-labeled tasks. 
        
        Get the ML backend ID by [listing the ML backends for a project](https://labelstud.io/api/#operation/api_ml_list).
        """,
        manual_parameters=[
            openapi.Parameter(
                name='id',
                type=openapi.TYPE_INTEGER,
                in_=openapi.IN_PATH,
                description='A unique integer value identifying this ML backend.',
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'use_ground_truth': openapi.Schema(
                    type=openapi.TYPE_BOOLEAN, description='Whether to include ground truth annotations in training'
                )
            },
        ),
        responses={
            200: openapi.Response(title='Training OK', description='Training has successfully started.'),
            500: openapi.Response(
                description='Training error',
                schema=openapi.Schema(
                    title='Error message',
                    description='Error message',
                    type=openapi.TYPE_STRING,
                    example='Server responded with an error.',
                ),
            ),
        },
    ),
)
class MLBackendTrainAPI(APIView):

    permission_required = all_permissions.projects_change

    def post(self, request, *args, **kwargs):
        ml_backend = generics.get_object_or_404(MLBackend, pk=self.kwargs['pk'])
        self.check_object_permissions(self.request, ml_backend)

        ml_backend.train()
        return Response(status=status.HTTP_200_OK)


@method_decorator(
    name='post',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='Predict',
        operation_description="""
        After you add an ML backend, call this API with the ML backend ID to run a test prediction on specific task data               
        """,
        manual_parameters=[
            openapi.Parameter(
                name='id',
                type=openapi.TYPE_INTEGER,
                in_=openapi.IN_PATH,
                description='A unique integer value identifying this ML backend.',
            ),
        ],
        responses={
            200: openapi.Response(title='Predicting OK', description='Predicting has successfully started.'),
            500: openapi.Response(
                description='Predicting error',
                schema=openapi.Schema(
                    title='Error message',
                    description='Error message',
                    type=openapi.TYPE_STRING,
                    example='Server responded with an error.',
                ),
            ),
        },
    ),
)
class MLBackendPredictTestAPI(APIView):
    serializer_class = MLBackendSerializer
    permission_required = all_permissions.projects_change

    def post(self, request, *args, **kwargs):
        ml_backend = generics.get_object_or_404(MLBackend, pk=self.kwargs['pk'])
        self.check_object_permissions(self.request, ml_backend)

        random = request.query_params.get('random', False)
        if random:
            task = Task.get_random(project=ml_backend.project)
            if not task:
                raise Http404

            kwargs = ml_backend._predict(task)
            return Response(**kwargs)

        else:
            return Response(
                status=status.HTTP_501_NOT_IMPLEMENTED,
                data={'error': 'Not implemented - you must provide random=true query parameter'},
            )


@method_decorator(
    name='post',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='Request Interactive Annotation',
        operation_description="""
        Send a request to the machine learning backend set up to be used for interactive preannotations to retrieve a
        predicted region based on annotator input. 
        See [set up machine learning](https://labelstud.io/guide/ml.html#Get-interactive-preannotations) for more.
        """,
        manual_parameters=[
            openapi.Parameter(
                name='id',
                type=openapi.TYPE_INTEGER,
                in_=openapi.IN_PATH,
                description='A unique integer value identifying this ML backend.',
            ),
        ],
        request_body=MLInteractiveAnnotatingRequest,
        responses={
            200: openapi.Response(title='Annotating OK', description='Interactive annotation has succeeded.'),
        },
    ),
)
class MLBackendInteractiveAnnotating(APIView):
    """
    Send a request to the machine learning backend set up to be used for interactive preannotations to retrieve a
    predicted region based on annotator input.
    """

    permission_required = all_permissions.tasks_view

    def _error_response(self, message, log_function=logger.info):
        log_function(message)
        return Response({'errors': [message]}, status=status.HTTP_200_OK)

    def _get_task(self, ml_backend, validated_data):
        return generics.get_object_or_404(Task, pk=validated_data['task'], project=ml_backend.project)

    def _get_credentials(self, request, context, project):
        if flag_set('ff_back_dev_2362_project_credentials_060722_short', request.user):
            context.update(
                project_credentials_login=project.task_data_login,
                project_credentials_password=project.task_data_password,
            )
        return context

    def post(self, request, *args, **kwargs):
        """
        Send a request to the machine learning backend set up to be used for interactive preannotations to retrieve a
        predicted region based on annotator input.
        """
        ml_backend = generics.get_object_or_404(MLBackend, pk=self.kwargs['pk'])
        self.check_object_permissions(self.request, ml_backend)
        serializer = MLInteractiveAnnotatingRequest(data=request.data)
        serializer.is_valid(raise_exception=True)

        task = self._get_task(ml_backend, serializer.validated_data)
        context = self._get_credentials(request, serializer.validated_data.get('context', {}), task.project)

        result = ml_backend.interactive_annotating(task, context, user=request.user)

        return Response(
            result,
            status=status.HTTP_200_OK,
        )


@method_decorator(
    name='get',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='Get model versions',
        operation_description='Get available versions of the model.',
        responses={'200': 'List of available versions.'},
    ),
)
class MLBackendVersionsAPI(generics.RetrieveAPIView):

    permission_required = all_permissions.projects_change

    def get(self, request, *args, **kwargs):
        ml_backend = generics.get_object_or_404(MLBackend, pk=self.kwargs['pk'])
        self.check_object_permissions(self.request, ml_backend)
        versions_response = ml_backend.get_versions()
        if versions_response.status_code == 200:
            result = {'versions': versions_response.response.get('versions', [])}
            return Response(data=result, status=200)
        elif versions_response.status_code == 404:
            result = {'versions': [ml_backend.model_version], 'message': 'Upgrade your ML backend version to latest.'}
            return Response(data=result, status=200)
        else:
            result = {'error': str(versions_response.error_message)}
            status_code = versions_response.status_code if versions_response.status_code > 0 else 500
            return Response(data=result, status=status_code)


@method_decorator(
    name='get',
    decorator=swagger_auto_schema(
        tags=['Machine Learning'],
        operation_summary='Get available models',
        operation_description='Get available models.',
        responses={'200': 'List of available models.'},
    ),
)
class MLBackendModelsAPI(generics.RetrieveAPIView):

    permission_required = all_permissions.projects_change

    def get(self, request, *args, **kwargs):
        available_models_response = self.get_available_models()
        if available_models_response.get('status') == 200:
            result = available_models_response.get('inferenceServices', [])
            return Response(data=result, status=200)
        elif available_models_response.get('status') == 404:
            return Response(data={}, status=404)
        else:
            result = {'error': str(available_models_response.error_message)}
            status_code = available_models_response.status_code if available_models_response.status_code > 0 else 500
            return Response(data=result, status=status_code)

    def get_available_models(self):
        auth_session = self.get_istio_auth_session(
            url=KF_API_URL,
            username=KF_USERNAME,
            password=KF_PASSWORD,
            tls_verify=KSERVE_TLS_VERIFY
        )

        # Create the cookies
        assert ("session_cookie" in auth_session and auth_session["session_cookie"].startswith("authservice_session="))
        cookie = auth_session["session_cookie"]

        resp = requests.get(KF_MODELS_API_URL, headers={"Cookie": cookie})
        return resp.json()

    # --
    # This function, get_istio_auth_session, was directly copy-pasted from Kubeflow's official website: https://www.kubeflow.org/docs/components/pipelines/v1/sdk/connect-api/
    # --
    def get_istio_auth_session(self, url: str, username: str, password: str, tls_verify: bool) -> dict:
        """
        Determine if the specified URL is secured by Dex and try to obtain a session cookie.
        WARNING: only Dex `staticPasswords` and `LDAP` authentication are currently supported
                 (we default default to using `staticPasswords` if both are enabled)

        :param url: Kubeflow server URL, including protocol
        :param username: Dex `staticPasswords` or `LDAP` username
        :param password: Dex `staticPasswords` or `LDAP` password
        :return: auth session information
        """
        # define the default return object
        auth_session = {
            "endpoint_url": url,  # KF endpoint URL
            "redirect_url": None,  # KF redirect URL, if applicable
            "dex_login_url": None,  # Dex login URL (for POST of credentials)
            "is_secured": None,  # True if KF endpoint is secured
            "session_cookie": None  # Resulting session cookies in the form "key1=value1; key2=value2"
        }

        # use a persistent session (for cookies)
        with requests.Session() as s:

            ################
            # Determine if Endpoint is Secured
            ################
            resp = s.get(url, allow_redirects=True, verify=tls_verify)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"HTTP status code '{resp.status_code}' for GET against: {url}"
                )

            auth_session["redirect_url"] = resp.url

            # if we were NOT redirected, then the endpoint is UNSECURED
            if len(resp.history) == 0:
                auth_session["is_secured"] = False
                return auth_session
            else:
                auth_session["is_secured"] = True

            ################
            # Get Dex Login URL
            ################
            redirect_url_obj = urlsplit(auth_session["redirect_url"])

            # if we are at `/auth?=xxxx` path, we need to select an auth type
            if re.search(r"/auth$", redirect_url_obj.path):
                #######
                # TIP: choose the default auth type by including ONE of the following
                #######

                # OPTION 1: set "staticPasswords" as default auth type
                redirect_url_obj = redirect_url_obj._replace(
                    path=re.sub(r"/auth$", "/auth/local", redirect_url_obj.path)
                )
                # OPTION 2: set "ldap" as default auth type
                # redirect_url_obj = redirect_url_obj._replace(
                #     path=re.sub(r"/auth$", "/auth/ldap", redirect_url_obj.path)
                # )

            # if we are at `/auth/xxxx/login` path, then no further action is needed (we can use it for login POST)
            if re.search(r"/auth/.*/login$", redirect_url_obj.path):
                auth_session["dex_login_url"] = redirect_url_obj.geturl()

            # else, we need to be redirected to the actual login page
            else:
                # this GET should redirect us to the `/auth/xxxx/login` path
                resp = s.get(redirect_url_obj.geturl(), allow_redirects=True, verify=tls_verify)
                if resp.status_code != 200:
                    raise RuntimeError(
                        f"HTTP status code '{resp.status_code}' for GET against: {redirect_url_obj.geturl()}"
                    )

                # set the login url
                auth_session["dex_login_url"] = resp.url

            ################
            # Attempt Dex Login
            ################
            resp = s.post(
                auth_session["dex_login_url"],
                data={"login": username, "password": password},
                allow_redirects=True,
                verify=tls_verify
            )
            if len(resp.history) == 0:
                raise RuntimeError(
                    f"Login credentials were probably invalid - "
                    f"No redirect after POST to: {auth_session['dex_login_url']}"
                )

            # store the session cookies in a "key1=value1; key2=value2" string
            auth_session["session_cookie"] = "; ".join([f"{c.name}={c.value}" for c in s.cookies])

        return auth_session
