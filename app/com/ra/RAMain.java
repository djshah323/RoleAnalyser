/**
 * 
 */
package com.ra;

import play.mvc.Controller;
import play.mvc.Result;
import views.*;

/**
 * @author SDhaval
 *
 */
public class RAMain extends Controller
{
    public static Result index() {
        return ok(index.render("Testing my application again"));
    }
}
