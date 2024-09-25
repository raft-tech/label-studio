import { useState } from 'react';
import { Button } from '../../../components';
import { ErrorWrapper } from '../../../components/Error/Error';
import { InlineError } from '../../../components/Error/InlineError';
import {
  Form,
  Input,
  Select,
  TextArea,
  Toggle
} from '../../../components/Form';
import './MachineLearningSettings.styl';

const CustomBackendForm = ({ action, backend, models, project, onSubmit }) => {

  /**
   * Sets selected model name from existing backend
   * OR if there is no existing backend, use the first model in the map
   * OR '' if there is no existing backend AND there are no models available
   */
  const getInitialSelectedModelNameState = (backend, models) => {
    if (backend) {
      return backend['selected_model_name'];
    } else if (Array.from(models).length > 0) {
      return Array.from(models)[0][0];
    } else {
      return '';
    }
  };

  const [selectedAuthMethod, setAuthMethod] = useState('');
  const [selectedModelName, setSelectedModelName] = useState(getInitialSelectedModelNameState(backend, models));
  const [, setMLError] = useState();


  return (
    <Form
      action={action}
      formData={{ ...(backend ?? {}) }}
      params={{ pk: backend?.id }}
      onSubmit={async (response) => {
        if (!response.error_message) {
          onSubmit(response);
        }
      }}
    >
      <Input type="hidden" name="project" value={project.id}/>

      <Form.Row columnCount={1}>
        <Input name="title" label="Name" placeholder="Enter a name" required/>
      </Form.Row>

      <Form.Row columnCount={1}>
        <Input name="url" label="Backend URL" required/>
      </Form.Row>

      <Form.Row columnCount={2}>
        <Select
          name="selected_model_name"
          label="Select an available model"
          options={Array.from(models).map((m) => ({ 'label':m[0], 'value': m[1].metadata.name }))}
          onChange={(e) => {
            setSelectedModelName(e.target.value);
          }}
        />
      </Form.Row>

      <Form.Row columnCount={2}>
        <Select
          name="auth_method"
          label="Select authentication method"
          options={[
            { label: 'No Authentication', value: 'NONE' },
            { label: 'Basic Authentication', value: 'BASIC_AUTH' },
          ]}
          onChange={(e) => {
            setAuthMethod(e.target.value);
          }}
        />
      </Form.Row>

      {(backend?.auth_method == 'BASIC_AUTH' || selectedAuthMethod == 'BASIC_AUTH') && (
        <Form.Row columnCount={2}>
          <Input name="basic_auth_user" label="Basic auth user"/>
          {backend?.basic_auth_pass_is_set ? (
            <Input name="basic_auth_pass" label="Basic auth pass" type="password"
              placeholder="********" />
          ) : (
            <Input name="basic_auth_pass" label="Basic auth pass" type="password"/>
          )}
        </Form.Row>
      )}

      <Form.Row columnCount={1}>
        <TextArea
          name="extra_params"
          label="Any extra params to pass during model connection"
          style={{ minHeight: 120 }}
        />
      </Form.Row>

      <Form.Row columnCount={1}>
        <Toggle
          name="is_interactive"
          label="Interactive preannotations"
          description="If enabled some labeling tools will send requests to the ML Backend interactively during the annotation process."
        />
      </Form.Row>

      <Form.Actions>
        <Button type="submit" look="primary" onClick={() => setMLError(null)}>
          Validate and Save
        </Button>
      </Form.Actions>

      <Form.ResponseParser>
        {(response) => (
          <>
            {response.error_message && (
              <ErrorWrapper
                error={{
                  response: {
                    detail: `Failed to ${
                      backend ? 'save' : 'add new'
                    } ML backend.`,
                    exc_info: response.error_message,
                  },
                }}
              />
            )}
          </>
        )}
      </Form.ResponseParser>

      <InlineError/>
    </Form>
  );
};

export { CustomBackendForm };
