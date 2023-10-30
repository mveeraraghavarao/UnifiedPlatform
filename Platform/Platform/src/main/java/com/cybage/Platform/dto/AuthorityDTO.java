package com.cybage.Platform.dto;

public class AuthorityDTO
{
	private String authority;

	public AuthorityDTO(String authority)
	{
		this.authority = authority;
	}

	public String getAuthority()
	{
		return this.authority;
	}

	public void setAuthority(String authority)
	{
		this.authority = authority;
	}

	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof AuthorityDTO))
			return false;
		final AuthorityDTO other = (AuthorityDTO) o;
		if (!other.canEqual((Object) this))
			return false;
		final Object this$authority = this.getAuthority();
		final Object other$authority = other.getAuthority();
		if (this$authority == null ? other$authority != null : !this$authority.equals(other$authority))
			return false;
		return true;
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof AuthorityDTO;
	}

	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $authority = this.getAuthority();
		result = result * PRIME + ($authority == null ? 43 : $authority.hashCode());
		return result;
	}

	public String toString()
	{
		return "AuthorityDTO(authority=" + this.getAuthority() + ")";
	}
}
