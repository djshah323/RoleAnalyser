/**
 * 
 */
package com.ra.model;

import javax.persistence.Entity;
import javax.persistence.Id;

import play.db.ebean.Model;

/**
 * @author SDhaval
 *
 */
@Entity
public class Resource extends Model
{

    @Id
    public String resource_id;
    public String name;
    
}
