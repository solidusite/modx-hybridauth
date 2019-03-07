<?php
switch ($modx->event->name) {

    case 'OnHandleRequest':
        if ($modx->context->key != 'web' && !$modx->user->id) {
            if ($user = $modx->getAuthenticatedUser($modx->context->key)) {
                $modx->user = $user;
                $modx->getUser($modx->context->key);
            }
        }

        if ($modx->user->isAuthenticated($modx->context->key)) {
            if (!$modx->user->active || $modx->user->Profile->blocked) {
                $modx->runProcessor('security/logout');
                $modx->sendRedirect($modx->makeUrl($modx->getOption('site_start'), '', '', 'full'));
            }
        }

        if (!empty($_REQUEST['hauth_action']) || !empty($_REQUEST['hauth_done'])) {

            if(!empty($_REQUEST['redirect'])) $_SESSION['HybridAuth'][$modx->context->key]['redirect'] = $modx->getOption('source_url',$_REQUEST,$modx->getOption('redirect',$_REQUEST));
            else if(isset($_SESSION['HybridAuth'][$modx->context->key]['redirect'])) unset($_SESSION['HybridAuth'][$modx->context->key]['redirect']);

            $config = !empty($_SESSION['HybridAuth'][$modx->context->key])
                ? $_SESSION['HybridAuth'][$modx->context->key]
                : array();

            $path = $modx->getOption('hybridauth.core_path','',MODX_CORE_PATH . 'components/hybridauth/')."model/hybridauth/";
            /** @var HybridAuth $HybridAuth */
            if ($HybridAuth = $modx->getService('HybridAuth', 'HybridAuth', $path, $config)) {
                if (!empty($_REQUEST['hauth_action'])) {
                    switch ($_REQUEST['hauth_action']) {
                        case 'login':
                            if (!empty($_REQUEST['provider'])) {
                                $HybridAuth->Login($_REQUEST['provider']);
                            } else {
                                $HybridAuth->Refresh();
                            }
                            break;
                        case 'logout':
                            $HybridAuth->Logout();
                            break;
                        case 'unbind':
                            if (!empty($_REQUEST['provider'])) {
                                $HybridAuth->runProcessor('web/service/remove', array(
                                    'provider' => $_REQUEST['provider'],
                                ));
                            }
                            $HybridAuth->Refresh();
                            break;
                    }
                } else {
                    $HybridAuth->Login($_REQUEST['hauth_done']);
                }
            }
        }
        break;

    case 'OnWebAuthentication':
        $modx->event->_output = !empty($_SESSION['HybridAuth']['verified']);
        unset($_SESSION['HybridAuth']['verified']);
        break;

    case 'OnUserFormPrerender':
        /** @var modUser $user */
        if (!isset($user) || $user->get('id') < 1) {
            return;
        }
        $path = $modx->getOption('hybridauth.core_path','',MODX_CORE_PATH . 'components/hybridauth/')."model/hybridauth/";
        if ($HybridAuth = $modx->getService('HybridAuth', 'HybridAuth', $path)) {
            $HybridAuth->regManagerTab($modx->controller, $user);
        }
        break;
}