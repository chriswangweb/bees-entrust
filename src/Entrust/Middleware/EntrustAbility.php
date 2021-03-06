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

class EntrustAbility
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
	 * @param \Illuminate\Http\Request $request
	 * @param Closure $next
	 * @param $roles
	 * @param $permissions
	 * @param bool $validateAll
	 * @return mixed
	 */
	public function handle($request, Closure $next, $roles, $permissions, $validateAll = false)
	{
		$id = $request->session()->get('user')['id'];
		if (!User::where('id','=',$id)->first()->ability(explode('|', $roles), explode('|', $permissions), array('validate_all' => $validateAll))) {
			abort(403);
		}

		return $next($request);
	}
}
