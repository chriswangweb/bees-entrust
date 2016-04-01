<?php namespace Zizaco\Entrust\Middleware;

/**
 * This file is part of Entrust,
 * a role & permission management solution for Laravel.
 *
 * @license MIT
 * @package Zizaco\Entrust
 */

use App\User;
use Closure;
use Illuminate\Contracts\Auth\Guard;

class EntrustPermission
{
	protected $auth;

	/**
	 * Creates a new instance of the middleware.
	 *
	 * @param Guard $auth
	 */
	public function __construct(Guard $auth)
	{
		$this->auth = $auth;
	}

	/**
	 * Handle an incoming request.
	 *
	 * @param  \Illuminate\Http\Request $request
	 * @param  Closure $next
	 * @param  $permissions
	 * @return mixed
	 */
	public function handle($request, Closure $next, $permissions)
	{
		$siteId = $request->session()->get('site_id');
		$siteId = isset($siteId)?$siteId:1;
		$id = $request->session()->get('user')['id'];
		if (!User::where('id','=',$id)->first()->can(explode('|', $permissions),$siteId)) {
			abort(403);
		}

		return $next($request);
	}
}
