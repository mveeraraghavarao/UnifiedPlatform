package com.cybage.Platform.dto;

import java.util.Date;
import java.util.Set;

public class UserDTO
{
	private String username;
	private String token;
	private boolean accountNonExpired;
	private boolean accountNonLocked;
	private boolean credentialsNonExpired;
	private boolean enabled;
	private Date timeBeforeExpiration;
	private Date graceLoginsRemaining;
	private Set<AuthorityDTO> authorities;
	private String switchToken;
	private String firewallToken;

	public String getSwitchToken() {
		return switchToken;
	}

	public void setSwitchToken(String switchToken) {
		this.switchToken = switchToken;
	}

	public String getFirewallToken() {
		return firewallToken;
	}

	public void setFirewallToken(String firewallToken) {
		this.firewallToken = firewallToken;
	}

	public UserDTO()
	{
	}

	public String getUsername()
	{
		return this.username;
	}

	public String getToken()
	{
		return this.token;
	}

	public boolean isAccountNonExpired()
	{
		return this.accountNonExpired;
	}

	public boolean isAccountNonLocked()
	{
		return this.accountNonLocked;
	}

	public boolean isCredentialsNonExpired()
	{
		return this.credentialsNonExpired;
	}

	public boolean isEnabled()
	{
		return this.enabled;
	}

	public Date getTimeBeforeExpiration()
	{
		return this.timeBeforeExpiration;
	}

	public Date getGraceLoginsRemaining()
	{
		return this.graceLoginsRemaining;
	}

	public Set<AuthorityDTO> getAuthorities()
	{
		return this.authorities;
	}

	public void setUsername(String username)
	{
		this.username = username;
	}

	public void setToken(String token)
	{
		this.token = token;
	}

	public void setAccountNonExpired(boolean accountNonExpired)
	{
		this.accountNonExpired = accountNonExpired;
	}

	public void setAccountNonLocked(boolean accountNonLocked)
	{
		this.accountNonLocked = accountNonLocked;
	}

	public void setCredentialsNonExpired(boolean credentialsNonExpired)
	{
		this.credentialsNonExpired = credentialsNonExpired;
	}

	public void setEnabled(boolean enabled)
	{
		this.enabled = enabled;
	}

	public void setTimeBeforeExpiration(Date timeBeforeExpiration)
	{
		this.timeBeforeExpiration = timeBeforeExpiration;
	}

	public void setGraceLoginsRemaining(Date graceLoginsRemaining)
	{
		this.graceLoginsRemaining = graceLoginsRemaining;
	}

	public void setAuthorities(Set<AuthorityDTO> authorities)
	{
		this.authorities = authorities;
	}

	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof UserDTO))
			return false;
		final UserDTO other = (UserDTO) o;
		if (!other.canEqual((Object) this))
			return false;
		final Object this$username = this.getUsername();
		final Object other$username = other.getUsername();
		if (this$username == null ? other$username != null : !this$username.equals(other$username))
			return false;
		final Object this$token = this.getToken();
		final Object other$token = other.getToken();
		if (this$token == null ? other$token != null : !this$token.equals(other$token))
			return false;
		if (this.isAccountNonExpired() != other.isAccountNonExpired())
			return false;
		if (this.isAccountNonLocked() != other.isAccountNonLocked())
			return false;
		if (this.isCredentialsNonExpired() != other.isCredentialsNonExpired())
			return false;
		if (this.isEnabled() != other.isEnabled())
			return false;
		final Object this$timeBeforeExpiration = this.getTimeBeforeExpiration();
		final Object other$timeBeforeExpiration = other.getTimeBeforeExpiration();
		if (this$timeBeforeExpiration == null ? other$timeBeforeExpiration != null : !this$timeBeforeExpiration.equals(other$timeBeforeExpiration))
			return false;
		final Object this$graceLoginsRemaining = this.getGraceLoginsRemaining();
		final Object other$graceLoginsRemaining = other.getGraceLoginsRemaining();
		if (this$graceLoginsRemaining == null ? other$graceLoginsRemaining != null : !this$graceLoginsRemaining.equals(other$graceLoginsRemaining))
			return false;
		final Object this$authorities = this.getAuthorities();
		final Object other$authorities = other.getAuthorities();
		if (this$authorities == null ? other$authorities != null : !this$authorities.equals(other$authorities))
			return false;
		return true;
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof UserDTO;
	}

	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $username = this.getUsername();
		result = result * PRIME + ($username == null ? 43 : $username.hashCode());
		final Object $token = this.getToken();
		result = result * PRIME + ($token == null ? 43 : $token.hashCode());
		result = result * PRIME + (this.isAccountNonExpired() ? 79 : 97);
		result = result * PRIME + (this.isAccountNonLocked() ? 79 : 97);
		result = result * PRIME + (this.isCredentialsNonExpired() ? 79 : 97);
		result = result * PRIME + (this.isEnabled() ? 79 : 97);
		final Object $timeBeforeExpiration = this.getTimeBeforeExpiration();
		result = result * PRIME + ($timeBeforeExpiration == null ? 43 : $timeBeforeExpiration.hashCode());
		final Object $graceLoginsRemaining = this.getGraceLoginsRemaining();
		result = result * PRIME + ($graceLoginsRemaining == null ? 43 : $graceLoginsRemaining.hashCode());
		final Object $authorities = this.getAuthorities();
		result = result * PRIME + ($authorities == null ? 43 : $authorities.hashCode());
		return result;
	}

	public String toString()
	{
		return "UserDTO(username=" + this.getUsername() + ", token=" + this.getToken() + ", accountNonExpired=" + this.isAccountNonExpired() + ", accountNonLocked=" + this.isAccountNonLocked() + ", credentialsNonExpired=" + this.isCredentialsNonExpired() + ", enabled=" + this.isEnabled() + ", timeBeforeExpiration=" + this.getTimeBeforeExpiration() + ", graceLoginsRemaining=" + this.getGraceLoginsRemaining() + ", authorities=" + this.getAuthorities() + ")";
	}
}