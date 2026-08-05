<?php

/**
 * Invoice Ninja (https://invoiceninja.com).
 *
 * @link https://github.com/invoiceninja/invoiceninja source repository
 *
 * @copyright Copyright (c) 2026. Invoice Ninja LLC (https://invoiceninja.com)
 *
 * @license https://www.elastic.co/licensing/elastic-license
 */

namespace App\Http\Requests\EmailProvider;

use App\Http\Requests\Request;
use Illuminate\Validation\Rule;

class CheckEmailProviderRequest extends Request
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        /** @var \App\Models\User $user */
        $user = auth()->user();

        return $user->isAdmin();
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'email_sending_method' => [
                'required',
                'string',
                Rule::in([
                    'default',
                    'client_mailgun',
                    'client_postmark',
                    'client_brevo',
                    'client_ses',
                ]),
            ],
            'mailgun_secret' => 'required_if:email_sending_method,client_mailgun|string|nullable',
            'mailgun_domain' => 'required_if:email_sending_method,client_mailgun|string|nullable',
            'mailgun_endpoint' => 'nullable|string|in:api.mailgun.net,api.eu.mailgun.net',
            'postmark_secret' => 'required_if:email_sending_method,client_postmark|string|nullable',
            'brevo_secret' => 'required_if:email_sending_method,client_brevo|string|nullable',
            'ses_access_key' => 'required_if:email_sending_method,client_ses|string|nullable',
            'ses_secret_key' => 'required_if:email_sending_method,client_ses|string|nullable',
            'ses_region' => 'nullable|string',
            'ses_topic_arn' => 'nullable|string',
        ];
    }
}
